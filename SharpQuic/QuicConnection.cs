using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading.Tasks;
using SharpQuic.Frames;
using SharpQuic.Packets;
using SharpQuic.Tls;
using SharpQuic.Tls.Enums;

namespace SharpQuic;

public sealed class QuicConnection {
    readonly UdpClient client;

    readonly TlsClient tlsClient;

    internal readonly QuicPacketProtection protection;

    readonly QuicTransportParameters parameters;

    internal Stage initialStage;

    internal Stage handshakeStage;

    internal Stage applicationStage;

    readonly PacketWriter packetWriter;

    internal readonly EndpointType endpointType;

    internal readonly byte[] sourceConnectionId;

    internal byte[] destinationConnectionId;

    readonly TaskCompletionSource ready = new();

    public readonly TaskCompletionSource<byte[]> data = new();

    State state;

    HandshakeType cryptoType;
    int cryptoLength;

    MemoryStream cryptoStream = new();

    readonly ulong[] nextStreamIds = new ulong[2];

    readonly Dictionary<ulong, QuicStream> streams = [];

    QuicConnection(EndpointType endpointType, UdpClient client, QuicConfiguration configuration) {
        this.client = client;
        this.endpointType = endpointType;
        protection = new(endpointType, configuration.Parameters.InitialSourceConnectionId);

        parameters = configuration.Parameters;

        packetWriter = new(this);

        initialStage = new() {
            KeySet = new(CipherSuite.Aes128GcmSHA256)
        };

        tlsClient = new(configuration.Parameters, configuration.Protocols, configuration.CertificateChain) {
            InitialFragmentWriter = initialStage.FrameWriter,
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

    public QuicStream OpenBidirectionalStream() {
        ulong id = nextStreamIds[0]++;

        QuicStream stream = new(this, id << 2 | (endpointType == EndpointType.Client ? 0u : 1u));

        streams.Add(stream.Id, stream);

        return stream;
    }

    public QuicStream OpenUnidirectionalStream() {
        ulong id = nextStreamIds[1]++;

        QuicStream stream = new(this, id << 2 | 0b10 | (endpointType == EndpointType.Client ? 0u : 1u));

        streams.Add(stream.Id, stream);

        return stream;
    }

    public ValueTask<int> FlushAsync(byte[] token = null) {
        initialStage?.Write(packetWriter, PacketType.Initial, token);
        handshakeStage?.Write(packetWriter, PacketType.Handshake);
        applicationStage?.Write(packetWriter, PacketType.OneRtt);

        byte[] datagram = packetWriter.ToDatagram();

        Console.WriteLine($"Sending datagram: {datagram.Length}");

        return client.SendAsync(datagram);
    }

    async Task RunnerAsync() {
        try {
            while(true) {
                Console.WriteLine("Receiving");
                UdpReceiveResult result = await client.ReceiveAsync();

                Console.WriteLine($"Received datagram: {result.Buffer.Length}");

                client.Connect(result.RemoteEndPoint);

                MemoryStream stream = new(result.Buffer);

                while(stream.Position < stream.Length) {
                    Packet packet = protection.Unprotect(stream, initialStage?.KeySet, handshakeStage?.KeySet, applicationStage?.KeySet);

                    if(packet is null) {
                        Console.WriteLine("Invalid packet");
                        break;
                    }

                    if(packet is not RetryPacket) {
                        Console.WriteLine($"Unprotected packet: {packet.PacketType} {packet.PacketNumber} {packet.Payload.Length}");

                        HashSet<uint> received = packet.PacketType switch {
                            PacketType.Initial => initialStage.Received,
                            PacketType.Handshake => handshakeStage.Received,
                            PacketType.OneRtt => applicationStage.Received,
                            _ => throw new NotImplementedException()
                        };

                        if(!received.Add(packet.PacketNumber)) {
                            Console.WriteLine($"Duplicate");
                            continue;
                        }
                    } else
                        Console.WriteLine($"Retry packet");

                    if(state == State.Null && endpointType == EndpointType.Server && packet is InitialPacket) {
                        parameters.OriginalDestinationConnectionId = packet.DestinationConnectionId;
                    }
                    
                    await HandlePacketAsync(packet);

                    switch(packet.PacketType) {
                        case PacketType.Initial:
                            initialStage.FrameWriter.Ack(packet.PacketNumber);
                            break;
                        case PacketType.Handshake:
                            handshakeStage.FrameWriter.Ack(packet.PacketNumber);
                            break;
                        case PacketType.OneRtt:
                            applicationStage.FrameWriter.Ack(packet.PacketNumber);
                            break;
                    }

                    await HandleHandshakeAsync();

                    await FlushAsync();
                }
            }
        } catch(Exception e) {
            Console.WriteLine(e);

            if(!ready.Task.IsCompleted)
                ready.SetException(e);
        }
    }

    async Task HandlePacketAsync(Packet packet) {
        if(packet is RetryPacket retryPacket) {
            await SendClientHelloAsync(retryPacket.Token);

            return;
        }

        if(state == State.Null && packet is InitialPacket initialPacket)
            destinationConnectionId = initialPacket.SourceConnectionId;

        FrameReader reader = new() {
            stream = new MemoryStream(packet.Payload)
        };

        while(reader.stream.Position < reader.stream.Length) {
            Frame frame = reader.Read();

            switch(frame) {
                case CryptoFrame cryptoFrame:
                    if(handshakeStage is not null && packet is InitialPacket || applicationStage is not null && packet is HandshakePacket)
                        break;

                    long position = cryptoStream.Position;

                    cryptoStream.Position = cryptoStream.Length;

                    cryptoStream.Write(cryptoFrame.Data);

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
                case StreamFrame streamFrame:
                    streams[streamFrame.Id].Put(streamFrame.Data, streamFrame.Offset);

                    //data.SetResult(frame.Data);
                    //streams[]

                    break;
                case NewConnectionIdFrame:
                    //destinationConnectionId = frame.Data;

                    break;
                case HandshakeDoneFrame:
                    break;
            }
        }
    }

    async Task HandleHandshakeAsync() {
        if(state == State.Null && tlsClient.State >= TlsClient.TlsState.WaitEncryptedExtensions) {
            handshakeStage = new() {
                KeySet = new(CipherSuite.Aes128GcmSHA256)
            };

            tlsClient.HandshakeFragmentWriter = handshakeStage.FrameWriter;

            if(endpointType == EndpointType.Server) {
                tlsClient.SendServerHello();
                
                tlsClient.DeriveHandshakeSecrets();

                handshakeStage.KeySet.Generate(tlsClient.serverHandshakeSecret, tlsClient.clientHandshakeSecret);

                Console.WriteLine("Generated handshake keys.");

                tlsClient.SendServerHandshake();

                Console.WriteLine("Sending server handshake.");

                await FlushAsync();
            } else {
                tlsClient.DeriveHandshakeSecrets();

                handshakeStage.KeySet.Generate(tlsClient.clientHandshakeSecret, tlsClient.serverHandshakeSecret);

                Console.WriteLine("Generated handshake keys.");
            }
            
            //initialStage = null;

            state = State.Connected;
        }

        if(state == State.Connected && tlsClient.State == TlsClient.TlsState.Connected) {
            applicationStage = new() {
                KeySet = new(CipherSuite.Aes128GcmSHA256)
            };

            if(endpointType == EndpointType.Client) {
                tlsClient.SendClientFinished();

                await FlushAsync();

                tlsClient.DeriveApplicationSecrets();

                applicationStage.KeySet.Generate(tlsClient.clientApplicationSecret, tlsClient.serverApplicationSecret);
            } else {
                tlsClient.DeriveApplicationSecrets();

                applicationStage.KeySet.Generate(tlsClient.serverApplicationSecret, tlsClient.clientApplicationSecret);
            }

            //handshakeStage = null;

            ready.SetResult();

            state = State.Idle;
        }
    }

    ValueTask<int> SendClientHelloAsync(byte[] token = null) {
        tlsClient.SendClientHello();

        initialStage.FrameWriter.WritePaddingUntil(1200);

        return FlushAsync(token);
    }

    enum State {
        Null,
        Connected,
        Idle
    }
}
