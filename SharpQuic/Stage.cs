using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using SharpQuic.Frames;
using SharpQuic.IO;

namespace SharpQuic;

public sealed class Stage {
    readonly QuicConnection connection;

    public FrameWriter FrameWriter { get; } = new();

    public KeySet KeySet { get; init; }

    public HashSet<uint> Received { get; } = [];

    public CutInputStream CryptoInputStream { get; } = new(10240);

    public CutOutputStream CryptoOutputStream { get; } = new(10240);

    public int AckDelayExponent { get; set; } = 3;

    public int MaxAckDelay { get; set; } = -1;

    public long ProbeTimeout { get; private set; }

    public bool ProbeTimeoutEnabled { get; set; } = true;

    readonly StageType type;

    internal readonly SortedSet<uint> acks = [];

    readonly Dictionary<uint, PacketInfo> packets = [];

    readonly List<InFlightPacket> inFlightPackets = [];

    uint largestAcknowledged;

    const int InitialRtt = 333;

    const int PacketThreshold = 3;

    const int TimeThresholdNumerator = 9;
    const int TimeThresholdDenominator = 8;

    const int Granularity = 20;

    int latestRtt = -1;
    int minRtt;
    int smoothedRtt = InitialRtt;
    int rttVar = InitialRtt / 2;

    bool ackEliciting;

    uint nextPacketNumber;

    internal Stage(QuicConnection connection, StageType type) {
        this.connection = connection;
        this.type = type;

        if(type == StageType.Application)
            ProbeTimeoutEnabled = false;

        CalculateProbeTimeout();
    }

    public void Ack(uint packetNumber, bool ackEliciting) {
        lock(acks)
            acks.Add(packetNumber);

        this.ackEliciting |= ackEliciting;
    }

    public async Task PeerAckAsync(PacketWriter packetWriter, AckFrame frame) {
        bool ackEliciting = false;

        int FindInFlightPacket(uint number) {
            for(int i = 0; i < inFlightPackets.Count; i++)
                if(inFlightPackets[i].Number == number)
                    return i;

            return -1;
        }

        void RemoveInFlightPacket(int index) {
            if(connection.debugLogging)
                Console.WriteLine($"Confirmed: {inFlightPackets[index].Number}");

            ackEliciting |= inFlightPackets[index].AckEliciting;

            bool exists = packets.Remove(inFlightPackets[index].Number, out PacketInfo packet);

            if(packet.Type == PacketInfoType.Stream)
                connection.StreamPacketAck(inFlightPackets[index].Number, packet.StreamId);
            else if(packet.Acks?.Length > 0)
                acks.RemoveWhere(ack => packet.Acks.Contains(ack));

            int last = inFlightPackets.Count - 1;

            inFlightPackets[index] = inFlightPackets[last];

            inFlightPackets.RemoveAt(last);
        }

        void FindAndRemoveInFlightPacket(uint number) {
            int index = FindInFlightPacket(number);

            if(index < 0)
                return;

            RemoveInFlightPacket(index);
        }

        largestAcknowledged = Math.Max(largestAcknowledged, frame.LargestAcknowledged);

        int index = FindInFlightPacket(frame.LargestAcknowledged);

        bool newly = index >= 0;

        long sendTime = 0;

        if(newly) {
            sendTime = inFlightPackets[index].SendTime;

            RemoveInFlightPacket(index);
        }

        uint back = 1;

        for(; back <= frame.FirstAckRange; back++)
            FindAndRemoveInFlightPacket(frame.LargestAcknowledged - back);

        foreach(AckFrame.AckRange range in frame.AckRanges) {
            back += range.Gap + 1;

            uint toBack = back + range.AckRangeLength;

            for(; back <= toBack; back++)
                FindAndRemoveInFlightPacket(frame.LargestAcknowledged - back);
        }

        if(ackEliciting)
            CalculateProbeTimeout();

        bool first = latestRtt < 0;

        latestRtt = (int)((Stopwatch.GetTimestamp() - sendTime) * 1000 / Stopwatch.Frequency);

        if(newly && ackEliciting) {
            if(first) {
                minRtt = latestRtt;
                smoothedRtt = latestRtt;
                rttVar = latestRtt / 2;
            } else {
                minRtt = Math.Min(minRtt, latestRtt);

                int ackDelay = frame.AckDelay * (1 << AckDelayExponent);

                if(MaxAckDelay >= 0)
                    ackDelay = Math.Min(ackDelay, MaxAckDelay);

                int adjustedRtt = latestRtt;

                if(latestRtt >= minRtt + ackDelay)
                    adjustedRtt = latestRtt - ackDelay;

                smoothedRtt = (7 * smoothedRtt + adjustedRtt) / 8;

                int rttVarSample = Math.Abs(smoothedRtt - adjustedRtt);

                rttVar = (3 * rttVar + rttVarSample) / 4;

                if(connection.debugLogging) {
                    Console.WriteLine($"Latest RTT: {latestRtt}");
                    Console.WriteLine($"Min RTT: {minRtt}");
                    Console.WriteLine($"Smoothed RTT: {smoothedRtt}");
                    Console.WriteLine($"RTT Var: {rttVar}");
                }
            }
        }

        long time = Stopwatch.GetTimestamp();

        int threshold = Math.Max(TimeThresholdNumerator * Math.Max(smoothedRtt, latestRtt) / TimeThresholdDenominator, Granularity);

        int count = inFlightPackets.Count;

        bool writeAck = false;

        for(int i = 0; i < count; i++) {
            InFlightPacket packet = inFlightPackets[i];

            if(largestAcknowledged < packet.Number + PacketThreshold)
                continue;

            if((time - packet.SendTime) * 1000 / Stopwatch.Frequency < threshold)
                continue;

            await PacketLostAsync(packet.Number);

            inFlightPackets.RemoveAt(i);

            i--;
            count--;
        }


        if(writeAck) {
            WriteAck(packetWriter, true);

            await connection.SendAsync(packetWriter);
        }

        ValueTask<int> PacketLostAsync(uint number) {
            string stage = null;

            if(connection.initialStage == this)
                stage = "Initial";
            else if(connection.handshakeStage == this)
                stage = "Handshake";
            else if(connection.applicationStage == this)
                stage = "Application";

            bool exists = packets.Remove(number, out PacketInfo packet);

            if(connection.debugLogging)
                Console.WriteLine($"{stage}: Packet lost: {number} that {(exists ? "exists" : "doesn't exists")}");

            if(packet.Type == PacketInfoType.Stream)
                return connection.StreamPacketLostAsync(number, packet.StreamId);

            if(packet.Type == PacketInfoType.Crypto)
                WriteCrypto(packetWriter, packet.Offset, packet.Length, packet.Token);
            else if(packet.Type == PacketInfoType.HandshakeDone)
                WriteHandshakeDone(packetWriter);
            else if(packet.Type == PacketInfoType.MaxStreams)
                WriteMaxStreams(packetWriter);
            
            writeAck = true;

            return connection.SendAsync(packetWriter);
        }
    }

    public uint GetNextPacketNumber(bool ackEliciting) {
        uint number = Interlocked.Increment(ref nextPacketNumber);

        if(connection.debugLogging)
            Console.WriteLine($"{type}: Packet number {number}");

        inFlightPackets.Add(new(number, ackEliciting, Stopwatch.GetTimestamp()));

        if(ackEliciting)
            CalculateProbeTimeout();

        return number;
    }

    public uint GetNextPacketNumber(ulong streamId) {
        uint number = GetNextPacketNumber(true);

        packets.Add(number, new(PacketInfoType.Stream, PacketType.OneRtt, null, streamId, 0, 0, null));

        return number;
    }

    public async Task WriteCryptoAsync(PacketWriter packetWriter, byte[] data, byte[] token = null) {
        ulong position = CryptoOutputStream.MaxData;

        CryptoOutputStream.Write(data);

        ulong maxData = CryptoOutputStream.MaxData;

        while(position < maxData) {
            int length = Math.Min((int)(maxData - position), 1200 - packetWriter.Length);

            if(length > 0) {
                WriteCrypto(packetWriter, position, length, token);

                position += (ulong)length;
            } else
                await connection.SendAsync(packetWriter);
        }
    }

    void WriteCrypto(PacketWriter packetWriter, ulong offset, int length, byte[] token) {
        Span<byte> data = stackalloc byte[length];

        CryptoOutputStream.Read(data, offset);

        FrameWriter.WriteCrypto(data, offset);

        if(token is not null)
            FrameWriter.WritePaddingUntil(1200);
        else
            FrameWriter.WritePaddingUntil(20);

        uint number = GetNextPacketNumber(true);

        if(connection.debugLogging)
            Console.WriteLine($"Crypto {type}");

        PacketType packetType = type switch {
            StageType.Initial => PacketType.Initial,
            StageType.Handshake => PacketType.Handshake,
            _ => PacketType.OneRtt
        };

        packets.Add(number, new(PacketInfoType.Crypto, packetType, null, 0, offset, length, token));

        packetWriter.Write(packetType, number, FrameWriter.ToPayload(), token);
    }

    public void WriteAck(PacketWriter packetWriter, bool force) {
        if(acks.Count < 1 || !ackEliciting && !force)
            return;

        FrameWriter.WriteAck(acks);
        
        ackEliciting = false;

        FrameWriter.WritePaddingUntil(20);

        uint number = GetNextPacketNumber(false);

        PacketType packetType = type switch {
            StageType.Initial => PacketType.Initial,
            StageType.Handshake => PacketType.Handshake,
            _ => PacketType.OneRtt
        };

        packets.Add(number, new(PacketInfoType.Ack, packetType, [..acks], 0, 0, 0, null));

        packetWriter.Write(packetType, number, FrameWriter.ToPayload());
    }

    public void WriteMaxStreams(PacketWriter packetWriter) {
        FrameWriter.WriteMaxStreams(true, connection.maxBidirectionalStreams);
        FrameWriter.WriteMaxStreams(false, connection.maxUnidirectionalStreams);

        FrameWriter.WritePaddingUntil(20);

        uint number = GetNextPacketNumber(true);

        packets.Add(number, new(PacketInfoType.MaxStreams, PacketType.OneRtt, null, 0, 0, 0, null));

        packetWriter.Write(PacketType.OneRtt, number, FrameWriter.ToPayload());
    }

    public void WriteProbe(PacketWriter packetWriter) {
        if(type == StageType.Initial && latestRtt < 0) {
            WriteCrypto(packetWriter, packets[nextPacketNumber].Offset, packets[nextPacketNumber].Length, packets[nextPacketNumber].Token);

            return;
        }

        if(acks.Count > 0) {
            lock(acks)
                FrameWriter.WriteAck(acks);
        
            ackEliciting = false;
        }

        FrameWriter.WritePing();

        FrameWriter.WritePaddingUntil(20);

        uint number = GetNextPacketNumber(true);

        if(connection.debugLogging)
            Console.WriteLine($"Probe {type}");

        PacketType packetType = type switch {
            StageType.Initial => PacketType.Initial,
            StageType.Handshake => PacketType.Handshake,
            _ => PacketType.OneRtt
        };

        packets.Add(number, new(PacketInfoType.Ack, packetType, [..acks], 0, 0, 0, null));

        packetWriter.Write(packetType, number, FrameWriter.ToPayload());
    }

    public void WriteHandshakeDone(PacketWriter packetWriter) {
        FrameWriter.WriteHandshakeDone();

        FrameWriter.WritePaddingUntil(20);

        uint number = GetNextPacketNumber(true);

        PacketType packetType = type switch {
            StageType.Initial => PacketType.Initial,
            StageType.Handshake => PacketType.Handshake,
            _ => PacketType.OneRtt
        };

        packets.Add(number, new(PacketInfoType.HandshakeDone, packetType, null, 0, 0, 0, null));

        packetWriter.Write(packetType, number, FrameWriter.ToPayload());
    }

    public void CalculateProbeTimeout() {
        if(!ProbeTimeoutEnabled)
            ProbeTimeout = long.MaxValue;

        if(connection.debugLogging)
            Console.WriteLine(smoothedRtt + Math.Max(rttVar * 4, Granularity) + (type == StageType.Application ? MaxAckDelay : 0));

        ProbeTimeout = (Stopwatch.GetTimestamp() * 1000 / Stopwatch.Frequency) + smoothedRtt + Math.Max(rttVar * 4, Granularity) + (type == StageType.Application ? MaxAckDelay : 0);
    }

    readonly record struct InFlightPacket(uint Number, bool AckEliciting, long SendTime);

    readonly record struct PacketInfo(PacketInfoType Type, PacketType PacketType, uint[] Acks, ulong StreamId, ulong Offset, int Length, byte[] Token);

    enum PacketInfoType {
        Ack,
        Crypto,
        Stream,
        MaxStreams,
        HandshakeDone
    }
}
