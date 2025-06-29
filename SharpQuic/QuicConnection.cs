using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using SharpQuic.Frames;
using SharpQuic.IO;
using SharpQuic.Packets;
using SharpQuic.Tls;
using SharpQuic.Tls.Enums;

namespace SharpQuic;

public sealed class QuicConnection : IDisposable {
    internal Socket socket;

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

    ulong maxIdleTimeout;

    bool ackElicitingSended;

    internal long timeoutTimer;

    readonly TaskCompletionSource connected;

    readonly TaskCompletionSource ready = new();

    internal readonly CancellationTokenSource connectionSource;

    readonly Channel<QuicStream> channel = Channel.CreateUnbounded<QuicStream>(new() { SingleReader = true, SingleWriter = true });

    internal readonly bool debugLogging;

    readonly double debugInputPacketLoss;

    readonly double debugOutputPacketLoss;

    readonly int debugOutputDelay;

    public IPEndPoint LocalPoint { get; private set; }

    public IPEndPoint RemotePoint { get; internal set; }

    public string Protocol { get; private set; }

    internal State state;

    readonly bool clientAuthentication;

    ulong nextBidirectionalStreamId;

    ulong nextUnidirectionalStreamId;

    internal ulong maxBidirectionalStreams;

    internal ulong maxUnidirectionalStreams;

    ulong peerMaxBidirectionalStreams;

    ulong peerMaxUnidirectionalStreams;

    SemaphoreSlim openBidirectionalStreamSemaphore;

    SemaphoreSlim openUnidirectionalStreamSemaphore;

    readonly Dictionary<ulong, QuicStream> streams = [];

    internal bool writeMaxStreams;

    static int nextNumber;

    internal int number;

    ulong errorCode;

    ReadOnlyMemory<char> reasonPhrase;

    internal QuicConnection(EndpointType endpointType, QuicConfiguration configuration) {
        this.endpointType = endpointType;
        protection = new(endpointType, configuration.Parameters.InitialSourceConnectionId);

        parameters = configuration.Parameters;

        packetWriter = new(this);

        initialStage = new(this, StageType.Initial) {
            KeySet = new(CipherSuite.Aes128GcmSHA256)
        };

        tlsClient = new(configuration.Parameters, configuration.Protocols, configuration.CertificateChain, configuration.ChainPolicy);

        if(endpointType == EndpointType.Server)
            connected = new();

        connectionSource = new();

        timer = new(this);

        sourceConnectionId = configuration.Parameters.InitialSourceConnectionId;
        destinationConnectionId = RandomNumberGenerator.GetBytes(8);

        maxIdleTimeout = configuration.Parameters.MaxIdleTimeout;

        debugLogging = configuration.DebugLogging;

        debugInputPacketLoss = configuration.DebugInputPacketLoss;
        debugOutputPacketLoss = configuration.DebugOutputPacketLoss;

        debugOutputDelay = configuration.DebugOutputDelay;

        clientAuthentication = configuration.ClientAuthentication;

        maxBidirectionalStreams = configuration.Parameters.InitialMaxStreamsBidi;
        maxUnidirectionalStreams = configuration.Parameters.InitialMaxStreamsUni;

        number = Interlocked.Increment(ref nextNumber);
    }

    public static async Task<QuicConnection> ConnectAsync(QuicConfiguration configuration) {
        configuration.Parameters.InitialSourceConnectionId = RandomNumberGenerator.GetBytes(8);

        QuicConnection connection = new(EndpointType.Client, configuration) {
            RemotePoint = configuration.RemotePoint
        };

        if(configuration.LocalPoint is not null)
            await QuicPort.SubscribeAsync(connection, configuration.LocalPoint, false);
        else
            connection.socket = QuicPort.CreateSocket();

        await connection.SendClientHelloAsync();

        connection.LocalPoint = (IPEndPoint)connection.socket.LocalEndPoint;

        if(configuration.LocalPoint is null)
            await QuicPort.SubscribeAsync(connection, (IPEndPoint)connection.socket.LocalEndPoint, connection.socket);

        connection.timer.Start();

        await connection.ready.Task.WaitAsync(configuration.HandshakeTimeout, configuration.CancellationToken);

        if(!connection.ready.Task.IsCompleted) {
            connection.Dispose();

            throw new QuicException();
        }

        return connection;
    }

    public static async Task<QuicConnection> ListenAsync(QuicConfiguration configuration) {
        configuration.Parameters.InitialSourceConnectionId = RandomNumberGenerator.GetBytes(8);

        QuicConnection connection = new(EndpointType.Server, configuration) {
            LocalPoint = configuration.LocalPoint
        };

        await QuicPort.SubscribeAsync(connection, configuration.LocalPoint, true);

        await connection.connected.Task.WaitAsync(configuration.CancellationToken);

        await connection.ready.Task.WaitAsync(configuration.HandshakeTimeout, configuration.CancellationToken);

        if(!connection.ready.Task.IsCompleted) {
            connection.Dispose();

            throw new QuicException();
        }

        return connection;
    }

    public async Task<QuicStream> OpenBidirectionalStream() {
        await openBidirectionalStreamSemaphore.WaitAsync(connectionSource.Token);

        ulong id = nextBidirectionalStreamId++;

        QuicStream stream = new(this, id << 2 | (endpointType == EndpointType.Client ? 0u : 1u), peerParameters.InitialMaxStreamDataBidiLocal);

        streams.Add(stream.Id, stream);

        return stream;
    }

    public async Task<QuicStream> OpenUnidirectionalStream() {
        await openUnidirectionalStreamSemaphore.WaitAsync(connectionSource.Token);

        ulong id = nextUnidirectionalStreamId++;

        QuicStream stream = new(this, id << 2 | 0b10 | (endpointType == EndpointType.Client ? 0u : 1u), peerParameters.InitialMaxStreamDataUni);

        streams.Add(stream.Id, stream);

        return stream;
    }

    public ValueTask<QuicStream> ReceiveStreamAsync() {
        return channel.Reader.ReadAsync(connectionSource.Token);
    }

    internal void StreamClosed(ulong id) {
        streams.Remove(id, out QuicStream stream);

        if(stream.Outside) {
            if(stream.Bidirectional)
                maxBidirectionalStreams++;
            else
                maxUnidirectionalStreams++;

            writeMaxStreams = true;
        }

        stream.Dispose();
    }

    internal ValueTask<int> SendAsync(PacketWriter packetWriter) {
        if(packetWriter.Length < 1)
            return ValueTask.FromResult(0);

        Memory<byte> datagram = packetWriter.ToDatagram();

        if(socket.LocalEndPoint is not null && Random.Shared.NextDouble() < debugOutputPacketLoss) {
            if(debugLogging)
                Console.WriteLine($"Losing datagram: {datagram.Length}");
            
            return ValueTask.FromResult(0);
        }

        if(debugLogging)
            Console.WriteLine($"Sending datagram: {datagram.Length}");

        if(debugOutputDelay > 0 && socket.LocalEndPoint is not null) {
            byte[] data = [..datagram.Span];

            Task.Run(async () => {
                await Task.Delay(debugOutputDelay);

                await socket.SendToAsync(data, RemotePoint);
            });

            return ValueTask.FromResult(0);
        }

        return socket.SendToAsync(datagram, RemotePoint);
    }

    internal ValueTask<int> FlushAsync() {
        initialStage?.WriteAck(packetWriter, false);
        handshakeStage?.WriteAck(packetWriter, false);
        applicationStage?.WriteAck(packetWriter, false);

        return SendAsync(packetWriter);
    }

    internal ValueTask StreamPacketLostAsync(uint number, ulong streamId) {
        return streams[streamId].PacketLostAsync(number);
    }

    internal void StreamPacketAck(uint number, ulong streamId) {
        if(streams.TryGetValue(streamId, out QuicStream stream))
            stream.PacketAck(number);
    }

    internal void OnSendAckElicitingPacket(long time) {
        if(ackElicitingSended)
            return;

        ackElicitingSended = true;

        CalculateTimeoutTimer(time);
    }

    void CalculateTimeoutTimer(long time) {
        if(maxIdleTimeout < 1)
            timeoutTimer = long.MaxValue;

        timeoutTimer = time * 1000 / Stopwatch.Frequency + (long)maxIdleTimeout;
    }

    async Task SendClientHelloAsync(byte[] token = null) {
        await initialStage.WriteCryptoAsync(packetWriter, tlsClient.SendClientHello(), token ?? []);

        await FlushAsync();
    }

    internal async Task ReceiveAsync(IPEndPoint point, byte[] data, int length) {
        if(Random.Shared.NextDouble() < debugInputPacketLoss) {
            if(debugLogging)
                Console.WriteLine($"Losed datagram: {length}");
            return;
        }

        if(debugLogging)
            Console.WriteLine($"Received datagram: {length}");

        MemoryStream stream = new(data, 0, length);

        while(stream.Position < stream.Length) {
            if(debugLogging)
                Console.WriteLine("Unprotecting");

            Packet packet = protection.Unprotect(stream, initialStage?.KeySet, handshakeStage?.KeySet, applicationStage?.KeySet);

            if(packet is null) {
                if(debugLogging)
                    Console.WriteLine("Invalid packet");
                return;
            }

            if(state == State.Initial && endpointType == EndpointType.Server) {
                if(debugLogging)
                    Console.WriteLine($"Connect to: {point}");
                RemotePoint = point;
            }

            if(packet is not RetryPacket) {
                if(debugLogging)
                    Console.WriteLine($"{number} Unprotected packet: {packet.PacketType} {packet.PacketNumber} {packet.Payload.Length}");

                HashSet<uint> received = packet.PacketType switch {
                    PacketType.Initial => initialStage.Received,
                    PacketType.Handshake => handshakeStage.Received,
                    PacketType.OneRtt => applicationStage.Received,
                    _ => throw new NotImplementedException()
                };

                if(!received.Add(packet.PacketNumber)) {
                    if(debugLogging)
                        Console.WriteLine($"Duplicate");
                    continue;
                }
            } else
                if(debugLogging)
                    Console.WriteLine($"Retry packet");
            
            await HandlePacketAsync(packet);

            await HandleHandshakeAsync();

            await FlushAsync();
        }
    }

    async Task HandlePacketAsync(Packet packet) {
        long time = Stopwatch.GetTimestamp();

        ackElicitingSended = false;

        CalculateTimeoutTimer(time);

        if(packet is RetryPacket retryPacket) {
            await SendClientHelloAsync(retryPacket.Token);

            return;
        }

        if(state == State.Initial && packet is InitialPacket initialPacket) {
            destinationConnectionId = initialPacket.SourceConnectionId;

            if(endpointType == EndpointType.Server) {
                parameters.OriginalDestinationConnectionId = packet.DestinationConnectionId;

                QuicPort.UnsubscribeListener();

                connected.SetResult();
            }
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
                case FrameType.ConnectionClose2:
                    break;
                default:
                    ackEliciting = true;
                    break;
            }

            switch(frame) {
                case AckFrame ackFrame:
                    switch(packet.PacketType) {
                        case PacketType.Initial:
                            await initialStage.PeerAckAsync(packetWriter, ackFrame, time);
                            break;
                        case PacketType.Handshake:
                            await handshakeStage.PeerAckAsync(packetWriter, ackFrame, time);
                            break;
                        case PacketType.OneRtt:
                            await applicationStage.PeerAckAsync(packetWriter, ackFrame, time);
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

                    await cryptoStream.WriteAsync(cryptoFrame.Data, cryptoFrame.Offset);

                    CutInputStreamReader cutStreamReader = new(cryptoStream);

                    if(debugLogging)
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

                        await channel.Writer.WriteAsync(stream, connectionSource.Token);
                    }

                    await stream.PutAsync(streamFrame.Data, streamFrame.Offset, streamFrame.Fin);

                    break;
                case MaxStreamDataFrame maxStreamDataFrame:
                    if(streams.TryGetValue(maxStreamDataFrame.Id, out stream))
                        stream.MaxStreamData(maxStreamDataFrame.MaxStreamData);

                    break;
                case MaxStreamsFrame maxStreamsFrame:
                    if(maxStreamsFrame.Bidirectional) {
                        if(maxStreamsFrame.MaxStreams > peerMaxBidirectionalStreams) {
                            openBidirectionalStreamSemaphore.Release((int)(maxStreamsFrame.MaxStreams - peerMaxBidirectionalStreams));
                            peerMaxBidirectionalStreams = maxStreamsFrame.MaxStreams;
                        }
                    } else {
                        if(maxStreamsFrame.MaxStreams > peerMaxUnidirectionalStreams) {
                            openUnidirectionalStreamSemaphore.Release((int)(maxStreamsFrame.MaxStreams - peerMaxUnidirectionalStreams));
                            peerMaxUnidirectionalStreams = maxStreamsFrame.MaxStreams;
                        }
                    }

                    break;
                case NewConnectionIdFrame:
                    //destinationConnectionId = frame.Data;

                    break;
                case ConnectionCloseFrame:
                    if(initialStage is not null) {
                        initialStage.WriteConnectionClose(packetWriter, 0, []);

                        await SendAsync(packetWriter);
                    }

                    if(handshakeStage is not null) {
                        handshakeStage.WriteConnectionClose(packetWriter, 0, []);

                        await SendAsync(packetWriter);
                    }

                    if(applicationStage is not null) {
                        applicationStage.WriteConnectionClose(packetWriter, 0, []);

                        await SendAsync(packetWriter);
                    }

                    Dispose();

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

        if(state == State.Closing) {
            switch(packet.PacketType) {
                case PacketType.Initial:
                    initialStage.WriteConnectionClose(packetWriter, errorCode, reasonPhrase.Span);
                    break;
                case PacketType.Handshake:
                    handshakeStage.WriteConnectionClose(packetWriter, errorCode, reasonPhrase.Span);
                    break;
                case PacketType.OneRtt:
                    applicationStage.WriteConnectionClose(packetWriter, errorCode, reasonPhrase.Span);
                    break;
            }

            await SendAsync(packetWriter);
        }
    }

    async Task HandleHandshakeAsync() {
        if(state == State.Initial && tlsClient.State >= TlsClient.TlsState.WaitingEncryptedExtensions) {
            handshakeStage = new(this, StageType.Handshake) {
                KeySet = new(tlsClient.CipherSuite)
            };

            if(endpointType == EndpointType.Server) {
                initialStage.CalculateProbeTimeout(Stopwatch.GetTimestamp());

                timer.Start();

                peerParameters = tlsClient.PeerParameters;

                maxIdleTimeout = Math.Min(parameters.MaxIdleTimeout, peerParameters.MaxIdleTimeout);

                if(maxIdleTimeout < 1)
                    maxIdleTimeout = Math.Max(parameters.MaxIdleTimeout, peerParameters.MaxIdleTimeout);

                initialStage.AckDelayExponent = peerParameters.AckDelayExponent;
                handshakeStage.AckDelayExponent = peerParameters.AckDelayExponent;

                await initialStage.WriteCryptoAsync(packetWriter, tlsClient.SendServerHello());
                
                tlsClient.DeriveHandshakeSecrets();

                handshakeStage.KeySet.Generate(tlsClient.serverHandshakeSecret, tlsClient.clientHandshakeSecret);

                if(debugLogging)
                    Console.WriteLine("Generated handshake keys.");

                await handshakeStage.WriteCryptoAsync(packetWriter, tlsClient.SendServerHandshake());

                if(clientAuthentication)
                    await handshakeStage.WriteCryptoAsync(packetWriter, tlsClient.SendCertificateRequest());
                else
                    await handshakeStage.WriteCryptoAsync(packetWriter, tlsClient.SendServerFinished());

                if(debugLogging)
                    Console.WriteLine("Sending server handshake.");
            } else {
                tlsClient.DeriveHandshakeSecrets();

                handshakeStage.KeySet.Generate(tlsClient.clientHandshakeSecret, tlsClient.serverHandshakeSecret);

                if(debugLogging)
                    Console.WriteLine("Generated handshake keys.");
            }

            state = State.Handshake;
        }

        if(state == State.Handshake && tlsClient.State == TlsClient.TlsState.WaitingFinishedOrCertificateRequest)
            if(endpointType == EndpointType.Client) {
                if(tlsClient.ClientAuthenticationRequested)
                    await handshakeStage.WriteCryptoAsync(packetWriter, tlsClient.SendClientCertificate());
            } else
                await handshakeStage.WriteCryptoAsync(packetWriter, tlsClient.SendServerFinished());

        if(state == State.Handshake && tlsClient.State == TlsClient.TlsState.Connected) {
            applicationStage = new(this, StageType.Application) {
                KeySet = new(tlsClient.CipherSuite)
            };

            initialStage = null;

            Protocol = tlsClient.Protocol;

            if(endpointType == EndpointType.Client) {
                peerParameters = tlsClient.PeerParameters;

                maxIdleTimeout = Math.Min(parameters.MaxIdleTimeout, peerParameters.MaxIdleTimeout);

                if(maxIdleTimeout < 1)
                    maxIdleTimeout = Math.Max(parameters.MaxIdleTimeout, peerParameters.MaxIdleTimeout);

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

            if(debugLogging)
                Console.WriteLine("Generated application keys.");

            peerMaxBidirectionalStreams = peerParameters.InitialMaxStreamsBidi;
            peerMaxUnidirectionalStreams = peerParameters.InitialMaxStreamsUni;

            openBidirectionalStreamSemaphore = new((int)peerParameters.InitialMaxStreamsBidi);
            openUnidirectionalStreamSemaphore = new((int)peerParameters.InitialMaxStreamsUni);

            ready.SetResult();

            state = State.Idle;
        }
    }

    public async Task CloseAsync(ulong errorCode, ReadOnlyMemory<char> reasonPhrase) {
        this.errorCode = errorCode;
        this.reasonPhrase = reasonPhrase;

        state = State.Closing;

        PacketWriter packetWriter = new(this);

        if(initialStage is not null) {
            initialStage.WriteConnectionClose(packetWriter, errorCode, reasonPhrase.Span);

            await SendAsync(packetWriter);
        }

        if(handshakeStage is not null) {
            handshakeStage.WriteConnectionClose(packetWriter, errorCode, reasonPhrase.Span);

            await SendAsync(packetWriter);
        }

        if(applicationStage is not null) {
            applicationStage.WriteConnectionClose(packetWriter, errorCode, reasonPhrase.Span);

            Console.WriteLine(packetWriter.Length);

            await SendAsync(packetWriter);
        }
    }

    public void Dispose() {
        state = State.Draining;

        connectionSource.Cancel();
        connectionSource.Dispose();

        openBidirectionalStreamSemaphore?.Dispose();
        openUnidirectionalStreamSemaphore?.Dispose();

        channel.Writer.Complete();

        QuicPort.Unsubscribe(this);

        foreach(QuicStream stream in streams.Values)
            stream.Dispose();
    }

    internal enum State {
        Initial,
        Handshake,
        Idle,
        Closing,
        Draining
    }
}
