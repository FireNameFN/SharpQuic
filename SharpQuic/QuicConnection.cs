using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using SharpQuic.Frames;
using SharpQuic.IO;
using SharpQuic.Packets;
using SharpQuic.Tls;
using SharpQuic.Tls.Enums;

namespace SharpQuic;

public sealed class QuicConnection : IDisposable {
    readonly UdpClient client = new();

    readonly TlsClient tlsClient;

    readonly ProbeTimeoutTimer timer;

    internal readonly QuicPacketProtection protection;

    internal readonly QuicTransportParameters parameters;

    internal QuicTransportParameters peerParameters;

    internal Stage initialStage;

    internal Stage handshakeStage;

    internal Stage applicationStage;

    readonly PacketWriter packetWriter;

    internal readonly EndpointType endpointType;

    internal readonly byte[] sourceConnectionId;

    internal byte[] destinationConnectionId;

    readonly TaskCompletionSource ready = new();

    readonly CancellationToken handshakeToken;

    internal readonly CancellationTokenSource connectionSource;

    readonly double debugInputPacketLoss;

    readonly double debugOutputPacketLoss;

    public string Protocol { get; private set; }

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

        initialStage = new(this, StageType.Initial) {
            KeySet = new(CipherSuite.Aes128GcmSHA256)
        };

        tlsClient = new(configuration.Parameters, configuration.Protocols, configuration.CertificateChain, configuration.ChainPolicy);
        
        handshakeToken = configuration.CancellationToken;

        connectionSource = CancellationTokenSource.CreateLinkedTokenSource(configuration.CancellationToken);

        timer = new(this);

        sourceConnectionId = configuration.Parameters.InitialSourceConnectionId;
        destinationConnectionId = RandomNumberGenerator.GetBytes(8);

        debugInputPacketLoss = configuration.DebugInputPacketLoss;
        debugOutputPacketLoss = configuration.DebugOutputPacketLoss;
    }

    public static async Task<QuicConnection> ConnectAsync(QuicConfiguration configuration) {
        configuration.Parameters.InitialSourceConnectionId = RandomNumberGenerator.GetBytes(8);

        QuicConnection connection = new(EndpointType.Client, configuration);

        connection.client.Connect(configuration.Point);

        await connection.SendClientHelloAsync();

        await connection.FlushAsync();

        await Task.Factory.StartNew(connection.RunnerAsync, TaskCreationOptions.LongRunning);

        await connection.timer.StartAsync();

        await connection.ready.Task;

        return connection;
    }

    public static async Task<QuicConnection> ListenAsync(QuicConfiguration configuration) {
        configuration.Parameters.InitialSourceConnectionId = RandomNumberGenerator.GetBytes(8);

        QuicConnection connection = new(EndpointType.Server, configuration);

        connection.client.Client.Bind(configuration.Point);

        await Task.Factory.StartNew(connection.RunnerAsync, TaskCreationOptions.LongRunning);

        await connection.timer.StartAsync();

        await connection.ready.Task;

        return connection;
    }

    public QuicStream OpenBidirectionalStream() {
        ulong id = nextBidirectionalStreamId++;

        QuicStream stream = new(this, id << 2 | (endpointType == EndpointType.Client ? 0u : 1u), peerParameters.InitialMaxStreamDataBidiLocal);

        streams.Add(stream.Id, stream);

        return stream;
    }

    public QuicStream OpenUnidirectionalStream() {
        ulong id = nextUnidirectionalStreamId++;

        QuicStream stream = new(this, id << 2 | 0b10 | (endpointType == EndpointType.Client ? 0u : 1u), peerParameters.InitialMaxStreamDataUni);

        streams.Add(stream.Id, stream);

        return stream;
    }

    public QuicStream ReceiveBidirectionalStream() {
        ulong id = nextPeerBidirectionalStreamId++;

        QuicStream stream = new(this, id << 2 | (endpointType == EndpointType.Server ? 0u : 1u), peerParameters.InitialMaxStreamDataBidiRemote);

        streams.Add(stream.Id, stream);

        return stream;
    }

    public QuicStream ReceiveUnidirectionalStream() {
        ulong id = nextPeerUnidirectionalStreamId++;

        QuicStream stream = new(this, id << 2 | 0b10 | (endpointType == EndpointType.Server ? 0u : 1u), 0);

        streams.Add(stream.Id, stream);

        return stream;
    }

    internal void StreamClosed(ulong id) {
        streams.Remove(id, out QuicStream stream);

        stream.Dispose();
    }

    internal ValueTask<int> SendAsync(PacketWriter packetWriter) {
        if(packetWriter.Length < 1)
            return ValueTask.FromResult(0);

        Memory<byte> datagram = packetWriter.ToDatagram();

        if(Random.Shared.NextDouble() < debugOutputPacketLoss) {
            Console.WriteLine($"Losing datagram: {datagram.Length}");
            
            return ValueTask.FromResult(0);
        }

        Console.WriteLine($"Sending datagram: {datagram.Length}");

        return client.SendAsync(datagram);
    }

    internal ValueTask<int> FlushAsync() {
        initialStage?.WriteAck(packetWriter, false);
        handshakeStage?.WriteAck(packetWriter, false);
        applicationStage?.WriteAck(packetWriter, false);

        return SendAsync(packetWriter);
    }

    internal ValueTask<int> StreamPacketLostAsync(uint number, ulong streamId) {
        return streams[streamId].PacketLostAsync(number);
    }

    internal void StreamPacketAck(uint number, ulong streamId) {
        streams[streamId].PacketAck(number);
    }

    async Task RunnerAsync() {
        try {
            long time = Stopwatch.GetTimestamp();

            while(true) {
                Console.WriteLine("Receiving");

                UdpReceiveResult result = await client.ReceiveAsync(state != State.Idle ? handshakeToken : connectionSource.Token);

                Console.WriteLine($"Time: {(Stopwatch.GetTimestamp() - time) * 1000 / Stopwatch.Frequency}");

                if(Random.Shared.NextDouble() < debugInputPacketLoss) {
                    Console.WriteLine($"Losed datagram: {result.Buffer.Length}");
                    
                    continue;
                }

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

            connectionSource.Cancel();

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
                case AckFrame ackFrame:
                    switch(packet.PacketType) {
                        case PacketType.Initial:
                            await initialStage.PeerAckAsync(ackFrame);
                            break;
                        case PacketType.Handshake:
                            await handshakeStage.PeerAckAsync(ackFrame);
                            break;
                        case PacketType.OneRtt:
                            await applicationStage.PeerAckAsync(ackFrame);
                            break;
                    }

                    break;
                case CryptoFrame cryptoFrame:
                    CutInputStream cryptoStream = packet.PacketType switch {
                        PacketType.Initial => initialStage.CryptoInputStream,
                        PacketType.Handshake => handshakeStage.CryptoInputStream,
                        PacketType.OneRtt => applicationStage.CryptoInputStream,
                        _ => throw new QuicException(),
                    };

                    cryptoStream.Write(cryptoFrame.Data, cryptoFrame.Offset);

                    CutInputStreamReader cutStreamReader = new(cryptoStream);

                    Console.WriteLine($"Got CRYPTO to {cryptoFrame.Offset + (ulong)cryptoFrame.Data.Length}. Available to read: {cutStreamReader.Length}");

                    while(cutStreamReader.Position < cutStreamReader.Length)
                        if(tlsClient.TryReceiveHandshake(cutStreamReader))
                            cryptoStream.AdvanceTo(cutStreamReader.Offset);
                        else
                            break;

                    break;
                case StreamFrame streamFrame:
                    if(!streams.TryGetValue(streamFrame.Id, out QuicStream stream)) {
                        stream = new(this, streamFrame.Id, (streamFrame.Id & 0b10) == 0 ? peerParameters.InitialMaxStreamDataBidiRemote : 0);

                        streams[streamFrame.Id] = stream;
                    }

                    stream.Put(streamFrame.Data, streamFrame.Offset, streamFrame.Fin);

                    break;
                case MaxStreamDataFrame maxStreamDataFrame:
                    if(!streams.TryGetValue(maxStreamDataFrame.Id, out stream)) {
                        stream = new(this, maxStreamDataFrame.Id, (maxStreamDataFrame.Id & 0b10) == 0 ? peerParameters.InitialMaxStreamDataBidiRemote : 0);

                        streams[maxStreamDataFrame.Id] = stream;
                    }

                    stream.MaxStreamData(maxStreamDataFrame.MaxStreamData);

                    break;
                case NewConnectionIdFrame:
                    //destinationConnectionId = frame.Data;

                    break;
                case HandshakeDoneFrame:
                    handshakeStage = null;

                    applicationStage.MaxAckDelay = Math.Max(parameters.MaxAckDelay, peerParameters.MaxAckDelay);
                    applicationStage.ProbeTimeoutEnabled = true;

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
            handshakeStage = new(this, StageType.Handshake) {
                KeySet = new(tlsClient.CipherSuite)
            };

            protection.CipherSuite = tlsClient.CipherSuite;

            if(endpointType == EndpointType.Server) {
                peerParameters = tlsClient.PeerParameters;

                initialStage.AckDelayExponent = peerParameters.AckDelayExponent;
                handshakeStage.AckDelayExponent = peerParameters.AckDelayExponent;

                await initialStage.WriteCryptoAsync(packetWriter, tlsClient.SendServerHello());
                
                tlsClient.DeriveHandshakeSecrets();

                handshakeStage.KeySet.Generate(tlsClient.serverHandshakeSecret, tlsClient.clientHandshakeSecret);

                Console.WriteLine("Generated handshake keys.");

                await handshakeStage.WriteCryptoAsync(packetWriter, tlsClient.SendServerHandshake());

                Console.WriteLine("Sending server handshake.");
            } else {
                tlsClient.DeriveHandshakeSecrets();

                handshakeStage.KeySet.Generate(tlsClient.clientHandshakeSecret, tlsClient.serverHandshakeSecret);

                Console.WriteLine("Generated handshake keys.");
            }

            state = State.Handshake;
        }

        if(state == State.Handshake && tlsClient.State == TlsClient.TlsState.Connected) {
            applicationStage = new(this, StageType.Application) {
                KeySet = new(tlsClient.CipherSuite)
            };

            initialStage = null;

            Protocol = tlsClient.Protocol;

            if(endpointType == EndpointType.Client) {
                peerParameters = tlsClient.PeerParameters;

                handshakeStage.AckDelayExponent = peerParameters.AckDelayExponent;
                applicationStage.AckDelayExponent = peerParameters.AckDelayExponent;

                await handshakeStage.WriteCryptoAsync(packetWriter, tlsClient.SendClientFinished());

                await FlushAsync();

                tlsClient.DeriveApplicationSecrets();

                applicationStage.KeySet.Generate(tlsClient.clientApplicationSecret, tlsClient.serverApplicationSecret);
            } else {
                applicationStage.AckDelayExponent = peerParameters.AckDelayExponent;

                tlsClient.DeriveApplicationSecrets();

                applicationStage.KeySet.Generate(tlsClient.serverApplicationSecret, tlsClient.clientApplicationSecret);

                applicationStage.WriteHandshakeDone(packetWriter);

                handshakeStage = null;
                
                applicationStage.MaxAckDelay = Math.Max(parameters.MaxAckDelay, peerParameters.MaxAckDelay);
                applicationStage.ProbeTimeoutEnabled = true;
            }

            Console.WriteLine("Generated application keys.");

            ready.SetResult();

            state = State.Idle;
        }
    }

    Task SendClientHelloAsync(byte[] token = null) {
        return initialStage.WriteCryptoAsync(packetWriter, tlsClient.SendClientHello(), token ?? []);
    }

    public void Dispose() {
        connectionSource.Cancel();
        connectionSource.Dispose();

        client.Dispose();

        foreach(QuicStream stream in streams.Values)
            stream.Dispose();
    }

    enum State {
        Initial,
        Handshake,
        Idle
    }
}
