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

    readonly PacketWriter initialPacketWriter;

    readonly PacketWriter handshakePacketWriter;

    readonly PacketWriter applicationPacketWriter;

    internal readonly byte[] sourceConnectionId;

    internal byte[] destinationConnectionId;

    readonly TaskCompletionSource ready = new();

    State state;

    HandshakeType cryptoType;
    int cryptoLength;

    MemoryStream cryptoStream = new();

    QuicConnection(EndpointType endpointType, UdpClient client, QuicConfiguration configuration) {
        this.client = client;
        protection = new(endpointType);

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
        QuicTransportParameters parameters = new() {
            InitialSourceConnectionId = RandomNumberGenerator.GetBytes(8)
        };

        QuicConnection connection = new(EndpointType.Client, new(), configuration);

        connection.client.Connect(configuration.Point);

        await connection.SendClientHelloAsync();

        //await Task.Factory.StartNew(connection.HandshakeRunner);

        await Task.Factory.StartNew(connection.RunnerAsync, TaskCreationOptions.LongRunning);

        await connection.ready.Task;

        /*UdpReceiveResult result = await connection.client.ReceiveAsync();

        MemoryStream stream = new(result.Buffer);

        InitialPacket packet = (InitialPacket)connection.protection.Unprotect(stream);

        FrameReader reader = new() {
            stream = new MemoryStream(packet.Payload)
        };

        Frame frame;

        do {
            frame = reader.Read();
        } while(frame.Type != FrameType.Crypto);

        connection.tlsClient.ReceiveHandshake(frame.Data);

        connection.tlsClient.DeriveHandshakeSecrets();

        connection.protection.GenerateKeys(connection.tlsClient.clientHandshakeSecret, connection.tlsClient.serverHandshakeSecret);*/

        return connection;
    }

    public static async Task<QuicConnection> ListenAsync(QuicConfiguration configuration) {
        configuration = configuration with {
            Parameters = configuration.Parameters with {
                InitialSourceConnectionId = RandomNumberGenerator.GetBytes(8)
            }
        };

        QuicConnection connection = new(EndpointType.Server, new(configuration.Point), configuration);

        await Task.Factory.StartNew(connection.RunnerAsync, TaskCreationOptions.LongRunning);

        await connection.ready.Task;

        /*UdpReceiveResult result = await connection.client.ReceiveAsync();

        MemoryStream stream = new(result.Buffer);

        InitialPacket packet = (InitialPacket)connection.protection.Unprotect(stream);

        FrameReader reader = new() {
            stream = new MemoryStream(packet.Payload)
        };

        Frame frame = reader.Read();

        connection.tlsClient.ReceiveHandshake(frame.Data);

        connection.tlsClient.SendServerHello();

        connection.initialPacketWriter.Write(PacketType.Initial, connection.initialFrameWriter.ToPayload());

        await connection.Flush();

        connection.tlsClient.DeriveHandshakeSecrets();

        connection.protection.GenerateKeys(connection.tlsClient.clientHandshakeSecret, connection.tlsClient.serverHandshakeSecret);*/

        /*connection.tlsClient.SendServerHandshake();

        packet = new() {
            DestinationConnectionId = packet.SourceConnectionId,
            SourceConnectionId = packet.DestinationConnectionId,
            Token = [],
            Payload = connection.handshakePacketWriter.stream.ToArray()
        };

        protectedPacket = connection.protection.Protect(packet);

        await connection.client.SendAsync(protectedPacket, result.RemoteEndPoint);

        result = await connection.client.ReceiveAsync();

        stream = new(result.Buffer);

        connection.protection.Unprotect(stream);

        result = await connection.client.ReceiveAsync();

        stream = new(result.Buffer);

        HandshakePacket handshakePacket = (HandshakePacket)connection.protection.Unprotect(stream);

        reader = new() {
            stream = new MemoryStream(handshakePacket.Payload)
        };

        do {
            frame = reader.Read();
        } while(frame.Type != FrameType.Crypto);

        connection.tlsClient.ReceiveHandshake(frame.Data);

        connection.tlsClient.DeriveApplicationSecrets();

        connection.protection.GenerateKeys(connection.tlsClient.clientApplicationSecret, connection.tlsClient.serverApplicationSecret);*/

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

                client.Connect(result.RemoteEndPoint);

                MemoryStream stream = new(result.Buffer);

                while(stream.Position < stream.Length) {
                    LongHeaderPacket packet = protection.Unprotect(stream);
                    
                    await HandlePacketAsync(packet);
                }
            }
        } catch(Exception e) {
            ready.SetException(e);
        }
    }

    async Task HandlePacketAsync(LongHeaderPacket packet) {
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
                    destinationConnectionId = packet.SourceConnectionId;

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

                            if(state == State.Null) {
                                if(protection.EndpointType == EndpointType.Server) {
                                    tlsClient.SendServerHello();
                            
                                    initialPacketWriter.Write();

                                    tlsClient.DeriveHandshakeSecrets();

                                    protection.GenerateKeys(tlsClient.clientHandshakeSecret, tlsClient.serverHandshakeSecret);

                                    tlsClient.SendServerHandshake();

                                    handshakePacketWriter.Write();

                                    await FlushAsync();
                                } else {
                                    tlsClient.DeriveHandshakeSecrets();

                                    protection.GenerateKeys(tlsClient.clientHandshakeSecret, tlsClient.serverHandshakeSecret);
                                }

                                state = State.Connected;
                            }

                            if(state == State.Connected && tlsClient.State == TlsClient.TlsState.Connected) {
                                if(protection.EndpointType == EndpointType.Client) {
                                    tlsClient.SendClientFinished();

                                    handshakePacketWriter.Write();

                                    await FlushAsync();
                                }

                                ready.SetResult();

                                state = State.Idle;
                            }

                            cryptoType = 0;
                        } else
                            break;
                    }

                    break;
            }
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
