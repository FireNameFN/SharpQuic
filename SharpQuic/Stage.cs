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

    readonly PacketWriter packetWriter;

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

    readonly SortedSet<uint> acks = [];

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
        packetWriter = new(connection);
        this.type = type;

        if(type == StageType.Application)
            ProbeTimeoutEnabled = false;

        CalculateProbeTimeout();
    }

    public void Ack(uint packetNumber, bool ackEliciting) {
        acks.Add(packetNumber);

        this.ackEliciting |= ackEliciting;
    }

    public async Task PeerAckAsync(AckFrame frame) {
        bool ackEliciting = false;

        int FindInFlightPacket(uint number) {
            for(int i = 0; i < inFlightPackets.Count; i++)
                if(inFlightPackets[i].Number == number)
                    return i;

            return -1;
        }

        void RemoveInFlightPacket(int index) {
            Console.WriteLine($"Confirmed: {inFlightPackets[index].Number}");

            ackEliciting |= inFlightPackets[index].AckEliciting;

            bool exists = packets.Remove(inFlightPackets[index].Number, out PacketInfo packet);

            if(packet.Acks?.Length > 0)
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

                Console.WriteLine($"Latest RTT: {latestRtt}");
                Console.WriteLine($"Min RTT: {minRtt}");
                Console.WriteLine($"Smoothed RTT: {smoothedRtt}");
                Console.WriteLine($"RTT Var: {rttVar}");
            }
        }

        long time = Stopwatch.GetTimestamp();

        int threshold = Math.Max(TimeThresholdNumerator * Math.Max(smoothedRtt, latestRtt) / TimeThresholdDenominator, Granularity);

        int count = inFlightPackets.Count;

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

        ValueTask<int> PacketLostAsync(uint number) {
            string stage = null;

            if(connection.initialStage == this)
                stage = "Initial";
            else if(connection.handshakeStage == this)
                stage = "Handshake";
            else if(connection.applicationStage == this)
                stage = "Application";

            bool exists = packets.Remove(number, out PacketInfo packet);

            Console.WriteLine($"{stage}: Packet lost: {number} that {(exists ? "exists" : "doesn't exists")}");

            if(packet.Acks is null) {
                if(packet.PacketType == PacketType.OneRtt)
                    return connection.StreamPacketLostAsync(number, packet.StreamId);

                WriteCrypto(packetWriter, packet.Offset, packet.Length, packet.Token);

                return connection.SendAsync(packetWriter);
            }

            if(acks.Count < 1)
                return ValueTask.FromResult(0);

            number = GetNextPacketNumber(FrameWriter.AckEliciting);

            packets.Add(number, new([..acks], packet.PacketType, 0, 0, 0, null));

            FrameWriter.WriteAck(acks);
            
            this.ackEliciting = false;

            FrameWriter.WritePaddingUntil(20);

            packetWriter.Write(packet.PacketType, number, FrameWriter.ToPayload(), null);

            return connection.SendAsync(packetWriter);
        }
    }

    public uint GetNextPacketNumber(bool ackEliciting) {
        uint number = Interlocked.Increment(ref nextPacketNumber);

        Console.WriteLine($"{type}: Packet number {number}");

        inFlightPackets.Add(new(number, ackEliciting, Stopwatch.GetTimestamp()));

        CalculateProbeTimeout();

        return number;
    }

    public uint GetNextPacketNumber(bool ackEliciting, ulong streamId) {
        uint number = GetNextPacketNumber(ackEliciting);

        packets.Add(number, new(null, PacketType.OneRtt, streamId, 0, 0, null));

        return number;
    }

    public void WriteCrypto(PacketWriter packetWriter, byte[] data, byte[] token = null) {
        CryptoOutputStream.Write(data);

        WriteCrypto(packetWriter, 0, data.Length, token);
    }

    void WriteCrypto(PacketWriter packetWriter, ulong offset, int length, byte[] token) {
        uint number = GetNextPacketNumber(FrameWriter.AckEliciting);

        Console.WriteLine($"Crypto {type}");

        PacketType packetType = type switch {
            StageType.Initial => PacketType.Initial,
            StageType.Handshake => PacketType.Handshake,
            _ => PacketType.OneRtt
        };

        packets.Add(number, new(null, packetType, 0, offset, length, token));
        
        Span<byte> data = stackalloc byte[length];

        CryptoOutputStream.Read(data, offset);

        FrameWriter.WriteCrypto(data, 0);

        if(token is not null)
            FrameWriter.WritePaddingUntil(1200);

        packetWriter.Write(packetType, number, FrameWriter.ToPayload(), token);
    }

    public void WriteProbe(PacketWriter packetWriter) {
        if(type == StageType.Initial && latestRtt < 0) {
            WriteCrypto(packetWriter, packets[nextPacketNumber].Offset, packets[nextPacketNumber].Length, packets[nextPacketNumber].Token);

            return;
        }

        uint number = GetNextPacketNumber(FrameWriter.AckEliciting);

        Console.WriteLine($"Probe {type}");

        PacketType packetType = type switch {
            StageType.Initial => PacketType.Initial,
            StageType.Handshake => PacketType.Handshake,
            _ => PacketType.OneRtt
        };

        packets.Add(number, new([..acks], packetType, 0, 0, 0, null));

        if(acks.Count > 0)
            FrameWriter.WriteAck(acks);

        FrameWriter.WritePing();
        
        ackEliciting = false;

        FrameWriter.WritePaddingUntil(20);

        packetWriter.Write(packetType, number, FrameWriter.ToPayload(), null);
    }

    public void CalculateProbeTimeout() {
        if(!ProbeTimeoutEnabled)
            ProbeTimeout = long.MaxValue;

        Console.WriteLine(smoothedRtt + Math.Max(rttVar * 4, Granularity) + (type == StageType.Application ? MaxAckDelay : 0));

        ProbeTimeout = (Stopwatch.GetTimestamp() * 1000 / Stopwatch.Frequency) + smoothedRtt + Math.Max(rttVar * 4, Granularity) + (type == StageType.Application ? MaxAckDelay : 0);
    }

    readonly record struct InFlightPacket(uint Number, bool AckEliciting, long SendTime);

    readonly record struct PacketInfo(uint[] Acks, PacketType PacketType, ulong StreamId, ulong Offset, int Length, byte[] Token);
}
