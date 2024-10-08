using System;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading.Tasks;
using SharpQuic.Packets;
using SharpQuic.Tls;
using SharpQuic.Tls.Enums;

namespace SharpQuic;

public sealed class QuicConnection {
    readonly UdpClient client;

    readonly TlsClient tlsClient;

    internal readonly QuicPacketProtection protection;

    readonly QuicTransportParameters parameters;

    readonly PacketWriter initialPacketWriter;

    readonly PacketWriter handshakePacketWriter;

    readonly PacketWriter applicationPacketWriter;

    internal readonly EndpointType endpointType;

    internal readonly byte[] sourceConnectionId;

    internal byte[] destinationConnectionId;

    readonly TaskCompletionSource ready = new();

    State state;

    HandshakeType cryptoType;
    int cryptoLength;

    MemoryStream cryptoStream = new();

    QuicConnection(EndpointType endpointType, UdpClient client, QuicConfiguration configuration) {
        this.client = client;
        this.endpointType = endpointType;
        protection = new(endpointType, configuration.Parameters.InitialSourceConnectionId);

        parameters = configuration.Parameters;

        initialPacketWriter = new(this, PacketType.Initial);
        handshakePacketWriter = new(this, PacketType.Handshake);
        applicationPacketWriter = new(this, 0);

        tlsClient = new(configuration.Parameters, configuration.Protocols, configuration.CertificateChain) {
            InitialFragmentWriter = initialPacketWriter.FrameWriter,
            HandshakeFragmentWriter = handshakePacketWriter.FrameWriter
        };

        sourceConnectionId = configuration.Parameters.InitialSourceConnectionId;
        destinationConnectionId = RandomNumberGenerator.GetBytes(8);
    }

    public static async Task<QuicConnection> ConnectAsync(QuicConfiguration configuration) {
        configuration.Parameters.InitialSourceConnectionId = RandomNumberGenerator.GetBytes(8);

        QuicConnection connection = new(EndpointType.Client, new(), configuration);

        connection.client.Connect(configuration.Point);

        await connection.SendClientHelloAsync();

        await Task.Factory.StartNew(connection.RunnerAsync, TaskCreationOptions.LongRunning);

        await connection.ready.Task;

        return connection;
    }

    public static async Task<QuicConnection> ListenAsync(QuicConfiguration configuration) {
        configuration.Parameters.InitialSourceConnectionId = RandomNumberGenerator.GetBytes(8);

        QuicConnection connection = new(EndpointType.Server, new(configuration.Point), configuration);

        await Task.Factory.StartNew(connection.RunnerAsync, TaskCreationOptions.LongRunning);

        await connection.ready.Task;

        return connection;
    }

    public ValueTask<int> FlushAsync() {
        MemoryStream stream = new();

        initialPacketWriter.CopyTo(stream);
        handshakePacketWriter.CopyTo(stream);
        applicationPacketWriter.CopyTo(stream);

        return client.SendAsync(stream.ToArray());
    }

    async Task RunnerAsync() {
        try {
            while(true) {
                UdpReceiveResult result = await client.ReceiveAsync();

                Console.WriteLine($"Received datagram: {result.Buffer.Length}");

                client.Connect(result.RemoteEndPoint);

                MemoryStream stream = new(result.Buffer);

                while(stream.Position < stream.Length) {
                    Packet packet = protection.Unprotect(stream);

                    if(packet is null)
                        break;

                    if(packet is not RetryPacket)
                        Console.WriteLine($"Unprotected packet: {packet.Payload.Length}");
                    else
                        Console.WriteLine($"Retry packet");

                    if(endpointType == EndpointType.Server && state == State.Null && packet is InitialPacket) {
                        parameters.OriginalDestinationConnectionId = packet.DestinationConnectionId;
                    }
                    
                    await HandlePacketAsync(packet);

                    switch(packet.PacketType) {
                        case PacketType.Initial:
                            initialPacketWriter.Ack(packet.PacketNumber);
                            break;
                        case PacketType.Handshake:
                            handshakePacketWriter.Ack(packet.PacketNumber);
                            break;
                        case PacketType.OneRtt:
                            applicationPacketWriter.Ack(packet.PacketNumber);
                            break;
                    }

                    await HandleHandshakeAsync();
                }
            }
        } catch(Exception e) {
            if(!ready.Task.IsCompleted)
                ready.SetException(e);
        }
    }

    async Task HandlePacketAsync(Packet packet) {
        if(packet is RetryPacket retryPacket) {
            await SendClientHelloAsync(retryPacket.Token);

            return;
        }

        FrameReader reader = new() {
            stream = new MemoryStream(packet.Payload)
        };

        while(reader.stream.Position < reader.stream.Length) {
            Frame frame = reader.Read();

            switch(frame.Type) {
                case FrameType.Crypto:
                    destinationConnectionId = ((LongHeaderPacket)packet).SourceConnectionId;

                    long position = cryptoStream.Position;

                    cryptoStream.Position = cryptoStream.Length;

                    cryptoStream.Write(frame.Data);

                    cryptoStream.Position = position;

                    while(true) {
                        if(cryptoType == 0 && cryptoStream.Length - cryptoStream.Position >= 4) {
                            byte[] data = new byte[4];

                            cryptoStream.ReadExactly(data);

                            (cryptoType, cryptoLength) = TlsClient.ReadHandshakeHeader(data);
                        }

                        if(cryptoStream.Length - cryptoStream.Position >= cryptoLength) {
                            byte[] data = new byte[cryptoLength];

                            cryptoStream.ReadExactly(data);

                            tlsClient.ReceiveHandshake(cryptoType, data);

                            cryptoType = 0;
                        } else
                            break;
                    }

                    break;
            }
        }
    }

    async Task HandleHandshakeAsync() {
        if(state == State.Null && tlsClient.State >= TlsClient.TlsState.WaitEncryptedExtensions) {
            if(endpointType == EndpointType.Server) {
                tlsClient.SendServerHello();
        
                initialPacketWriter.Write();
                
                tlsClient.DeriveHandshakeSecrets();

                protection.GenerateKeys(tlsClient.clientHandshakeSecret, tlsClient.serverHandshakeSecret);

                Console.WriteLine("Generated handshake keys.");

                tlsClient.SendServerHandshake();

                handshakePacketWriter.Write();

                Console.WriteLine("Sending server handshake.");

                await FlushAsync();
            } else {
                tlsClient.DeriveHandshakeSecrets();

                protection.GenerateKeys(tlsClient.clientHandshakeSecret, tlsClient.serverHandshakeSecret);

                Console.WriteLine("Generated handshake keys.");
            }

            state = State.Connected;
        }

        if(state == State.Connected && tlsClient.State == TlsClient.TlsState.Connected) {
            if(endpointType == EndpointType.Client) {
                tlsClient.SendClientFinished();

                handshakePacketWriter.Write();

                await FlushAsync();
            }

            tlsClient.DeriveApplicationSecrets();

            protection.GenerateKeys(tlsClient.clientApplicationSecret, tlsClient.serverApplicationSecret);

            ready.SetResult();

            state = State.Idle;
        }
    }

    ValueTask<int> SendClientHelloAsync(byte[] token = null) {
        tlsClient.SendClientHello();

        initialPacketWriter.FrameWriter.WritePaddingUntil1200();

        initialPacketWriter.Write(token);

        return FlushAsync();
    }

    enum State {
        Null,
        Connected,
        Idle
    }
}
