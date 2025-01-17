using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading.Tasks;
using SharpQuic.Frames;
using SharpQuic.IO;
using SharpQuic.Packets;
using SharpQuic.Tls;
using SharpQuic.Tls.Enums;

namespace SharpQuic;

public sealed class QuicConnection {
    readonly UdpClient client = new();

    readonly TlsClient tlsClient;

    internal readonly QuicPacketProtection protection;

    internal readonly QuicTransportParameters parameters;

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

    ulong nextBidirectionalStreamId;

    ulong nextUnidirectionalStreamId;

    ulong nextPeerBidirectionalStreamId;

    ulong nextPeerUnidirectionalStreamId;

    readonly Dictionary<ulong, QuicStream> streams = [];

    QuicConnection(EndpointType endpointType, QuicConfiguration configuration) {
        this.endpointType = endpointType;
        protection = new(endpointType, configuration.Parameters.InitialSourceConnectionId);

        parameters = configuration.Parameters;

        packetWriter = new(this);

        initialStage = new() {
            KeySet = new(CipherSuite.Aes128GcmSHA256)
        };

        tlsClient = new(configuration.Parameters, configuration.Protocols, configuration.CertificateChain);

        sourceConnectionId = configuration.Parameters.InitialSourceConnectionId;
        destinationConnectionId = RandomNumberGenerator.GetBytes(8);
    }

    public static async Task<QuicConnection> ConnectAsync(QuicConfiguration configuration) {
        configuration.Parameters.InitialSourceConnectionId = RandomNumberGenerator.GetBytes(8);

        QuicConnection connection = new(EndpointType.Client, configuration);

        connection.client.Connect(configuration.Point);

        await connection.SendClientHelloAsync();

        await Task.Factory.StartNew(connection.RunnerAsync, TaskCreationOptions.LongRunning);

        await connection.ready.Task;

        return connection;
    }

    public static async Task<QuicConnection> ListenAsync(QuicConfiguration configuration) {
        configuration.Parameters.InitialSourceConnectionId = RandomNumberGenerator.GetBytes(8);

        QuicConnection connection = new(EndpointType.Server, configuration);

        connection.client.Client.Bind(configuration.Point);

        await Task.Factory.StartNew(connection.RunnerAsync, TaskCreationOptions.LongRunning);

        await connection.ready.Task;

        return connection;
    }

    public QuicStream OpenBidirectionalStream() {
        ulong id = nextBidirectionalStreamId++;

        QuicStream stream = new(this, id << 2 | (endpointType == EndpointType.Client ? 0u : 1u));

        streams.Add(stream.Id, stream);

        return stream;
    }

    public QuicStream OpenUnidirectionalStream() {
        ulong id = nextUnidirectionalStreamId++;

        QuicStream stream = new(this, id << 2 | 0b10 | (endpointType == EndpointType.Client ? 0u : 1u));

        streams.Add(stream.Id, stream);

        return stream;
    }

    public QuicStream ReceiveBidirectionalStream() {
        ulong id = nextPeerBidirectionalStreamId++;

        QuicStream stream = new(this, id << 2 | (endpointType == EndpointType.Server ? 0u : 1u));

        streams.Add(stream.Id, stream);

        return stream;
    }

    public QuicStream ReceiveUnidirectionalStream() {
        ulong id = nextPeerUnidirectionalStreamId++;

        QuicStream stream = new(this, id << 2 | 0b10 | (endpointType == EndpointType.Server ? 0u : 1u));

        streams.Add(stream.Id, stream);

        return stream;
    }

    internal ValueTask<int> SendAsync(PacketWriter packetWriter) {
        byte[] datagram = packetWriter.ToDatagram();

        Console.WriteLine($"Sending datagram: {datagram.Length}");

        return client.SendAsync(datagram);
    }

    internal ValueTask<int> FlushAsync(byte[] token = null) {
        initialStage?.Write(packetWriter, PacketType.Initial, token);
        handshakeStage?.Write(packetWriter, PacketType.Handshake);
        applicationStage?.Write(packetWriter, PacketType.OneRtt);

        return SendAsync(packetWriter);
    }

    internal async Task SendCrypto(ReadOnlyMemory<byte> data, FrameWriter frameWriter) {
        int position = 0;

        while(position < data.Length) {
            int length = 1200 - frameWriter.Length;

            if(position + length > data.Length)
                length = data.Length - position;

            frameWriter.WriteCrypto(data.Slice(position, length).Span, (ulong)position);

            position += length;

            await FlushAsync();
        }
    }

    async Task RunnerAsync() {
        try {
            while(true) {
                Console.WriteLine("Receiving");

                UdpReceiveResult result = await client.ReceiveAsync();

                Console.WriteLine($"Received datagram: {result.Buffer.Length}");

                if(state == State.Initial && endpointType == EndpointType.Server)
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
                    
                    await HandlePacketAsync(packet);

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

        if(state == State.Initial && packet is InitialPacket initialPacket) {
            destinationConnectionId = initialPacket.SourceConnectionId;

            if(endpointType == EndpointType.Server)
                parameters.OriginalDestinationConnectionId = packet.DestinationConnectionId;
        }

        FrameReader reader = new() {
            stream = new MemoryStream(packet.Payload)
        };

        bool ackEliciting = false;

        while(reader.stream.Position < reader.stream.Length) {
            Frame frame = reader.Read();

            switch(frame?.Type) {
                case null:
                case FrameType.Ack:
                case FrameType.ConnectionClose:
                    break;
                default:
                    ackEliciting = true;
                    break;
            }

            switch(frame) {
                case CryptoFrame cryptoFrame:
                    if(handshakeStage is not null && packet is InitialPacket || applicationStage is not null && packet is HandshakePacket)
                        break;

                    CutStream cryptoStream = packet.PacketType switch {
                        PacketType.Initial => initialStage.CryptoStream,
                        PacketType.Handshake => handshakeStage.CryptoStream,
                        PacketType.OneRtt => applicationStage.CryptoStream,
                        _ => throw new QuicException(),
                    };

                    cryptoStream.Write(cryptoFrame.Data, cryptoFrame.Offset);

                    CutStreamReader cutStreamReader = new(cryptoStream);

                    while(cutStreamReader.Position < cutStreamReader.Length)
                        if(tlsClient.TryReceiveHandshake(cutStreamReader))
                            cryptoStream.AdvanceTo(cutStreamReader.Offset);
                        else
                            break;

                    break;
                case StreamFrame streamFrame:
                    if(!streams.TryGetValue(streamFrame.Id, out QuicStream stream)) {
                        stream = new(this, streamFrame.Id);

                        streams[streamFrame.Id] = stream;
                    }

                    stream.Put(streamFrame.Data, streamFrame.Offset, streamFrame.Fin);

                    break;
                case MaxStreamDataFrame maxStreamDataFrame:
                    if(!streams.TryGetValue(maxStreamDataFrame.Id, out stream)) {
                        stream = new(this, maxStreamDataFrame.Id);

                        streams[maxStreamDataFrame.Id] = stream;
                    }

                    stream.MaxStreamData(maxStreamDataFrame.MaxStreamData);

                    break;
                case NewConnectionIdFrame:
                    //destinationConnectionId = frame.Data;

                    break;
                case HandshakeDoneFrame:
                    initialStage = null;
                    handshakeStage = null;

                    break;
            }
        }

        switch(packet.PacketType) {
            case PacketType.Initial:
                initialStage.Ack(packet.PacketNumber, ackEliciting);
                break;
            case PacketType.Handshake:
                handshakeStage.Ack(packet.PacketNumber, ackEliciting);
                break;
            case PacketType.OneRtt:
                applicationStage.Ack(packet.PacketNumber, ackEliciting);
                break;
        }
    }

    async Task HandleHandshakeAsync() {
        if(state == State.Initial && tlsClient.State >= TlsClient.TlsState.WaitEncryptedExtensions) {
            handshakeStage = new() {
                KeySet = new(tlsClient.CipherSuite)
            };

            protection.CipherSuite = tlsClient.CipherSuite;

            if(endpointType == EndpointType.Server) {
                initialStage.FrameWriter.WriteCrypto(tlsClient.SendServerHello(), 0);
                
                tlsClient.DeriveHandshakeSecrets();

                handshakeStage.KeySet.Generate(tlsClient.serverHandshakeSecret, tlsClient.clientHandshakeSecret);

                Console.WriteLine("Generated handshake keys.");

                handshakeStage.FrameWriter.WriteCrypto(tlsClient.SendServerHandshake(), 0);

                Console.WriteLine("Sending server handshake.");

                await FlushAsync();
            } else {
                tlsClient.DeriveHandshakeSecrets();

                handshakeStage.KeySet.Generate(tlsClient.clientHandshakeSecret, tlsClient.serverHandshakeSecret);

                Console.WriteLine("Generated handshake keys.");
            }

            state = State.Handshake;
        }

        if(state == State.Handshake && tlsClient.State == TlsClient.TlsState.Connected) {
            applicationStage = new() {
                KeySet = new(tlsClient.CipherSuite)
            };

            if(endpointType == EndpointType.Client) {
                handshakeStage.FrameWriter.WriteCrypto(tlsClient.SendClientFinished(), 0);

                await FlushAsync();

                tlsClient.DeriveApplicationSecrets();

                applicationStage.KeySet.Generate(tlsClient.clientApplicationSecret, tlsClient.serverApplicationSecret);
            } else {
                tlsClient.DeriveApplicationSecrets();

                applicationStage.KeySet.Generate(tlsClient.serverApplicationSecret, tlsClient.clientApplicationSecret);
            }

            ready.SetResult();

            state = State.Idle;
        }
    }

    ValueTask<int> SendClientHelloAsync(byte[] token = null) {
        initialStage.FrameWriter.WriteCrypto(tlsClient.SendClientHello(), 0);

        initialStage.FrameWriter.WritePaddingUntil(1200);

        return FlushAsync(token);
    }

    enum State {
        Initial,
        Handshake,
        Idle
    }
}
