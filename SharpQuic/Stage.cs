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

    readonly SemaphoreSlim inFlightSemaphore = new(1, 1);

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

    internal double congestionWindow = InitialCongestionWindow;
    double maxCongestionWindow = InitialCongestionWindow;
    double slowStartThreshold = int.MaxValue;
    long epochStartTime = -1;

    double congestionK;

    uint recovery;

    const double Beta = 0.7;

    const double CongestionConstant = 0.4;

    const int InitialCongestionWindow = 10;
    const int MinCongestionWindow = 2;

    const int MaxSegmentSize = 1470;

    int bytesInFlight;

    internal readonly SemaphoreSlim congestionSemaphore = new(0, 1);

    bool ackEliciting;

    uint nextPacketNumber;

    readonly long time = Stopwatch.GetTimestamp();

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
        await inFlightSemaphore.WaitAsync();

        bool ackEliciting = false;

        int bytesAcked = 0;

        int FindInFlightPacket(uint number) {
            for(int i = 0; i < inFlightPackets.Count; i++)
                if(inFlightPackets[i].Number == number)
                    return i;

            return -1;
        }

        void RemoveInFlightPacket(int index) {
            if(connection.debugLogging)
                Console.WriteLine($"{connection.number} Confirmed: {inFlightPackets[index].Number}");

            ackEliciting |= inFlightPackets[index].AckEliciting;

            bytesAcked += inFlightPackets[index].Length;
            
            bool exists;
            PacketInfo packet;

            lock(packets)
                exists = packets.Remove(inFlightPackets[index].Number, out packet);

            if(packet.Type == PacketInfoType.Stream)
                connection.StreamPacketAck(inFlightPackets[index].Number, packet.StreamId);
            else if(packet.Acks?.Length > 0)
                lock(acks)
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

        bytesInFlight -= bytesAcked;

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

        if(type == StageType.Application) {
            if(congestionWindow < slowStartThreshold) {
                congestionWindow += (double)bytesAcked / MaxSegmentSize;
            } else {
                if(epochStartTime < 0) {
                    epochStartTime = time;

                    congestionK = Math.Cbrt((maxCongestionWindow - congestionWindow) / CongestionConstant);
                }

                double t = (double)(time - epochStartTime) / Stopwatch.Frequency + smoothedRtt / 1000d;

                double tmk = t - congestionK;

                double window = CongestionConstant * tmk * tmk * tmk + maxCongestionWindow;

                double target;

                if(window < congestionWindow)
                    target = congestionWindow;
                else
                    target = Math.Min(congestionWindow * 1.5, window);

                congestionWindow += (target - congestionWindow) / congestionWindow;
            }
        }

        int threshold = Math.Max(TimeThresholdNumerator * Math.Max(smoothedRtt, latestRtt) / TimeThresholdDenominator, Granularity);

        List<uint> lostPackets = [];
        
        int count = inFlightPackets.Count;

        bool writeAck = false;

        for(int i = 0; i < count; i++) {
            InFlightPacket packet = inFlightPackets[i];

            if(largestAcknowledged < packet.Number + PacketThreshold)
                continue;

            if((time - packet.SendTime) * 1000 / Stopwatch.Frequency < threshold)
                continue;

            lostPackets.Add(packet.Number);

            bytesInFlight -= packet.Length;

            inFlightPackets.RemoveAt(i);

            i--;
            count--;
        }

        inFlightSemaphore.Release();

        if(type == StageType.Application && lostPackets.Count > 0 && largestAcknowledged >= recovery) {
            maxCongestionWindow = congestionWindow;

            //slowStartThreshold = Math.Max((double)bytesInFlight / MaxSegmentSize * Beta, 2);
            slowStartThreshold = Math.Max(congestionWindow * Beta, 2);
            congestionWindow = slowStartThreshold;

            epochStartTime = -1;

            recovery = nextPacketNumber;

            //Console.WriteLine($"Lost {lostPackets.Count} packets. SRTT: {smoothedRtt}. Max: {maxCongestionWindow:F2}. CWND: {congestionWindow:F2}. Time: {(Stopwatch.GetTimestamp() - this.time) * 1000 / Stopwatch.Frequency}");
        }// else if(type == StageType.Application && lostPackets.Count > 0)
        //    Console.WriteLine($"Lost {lostPackets.Count} packets. SRTT: {smoothedRtt}. CWND: {congestionWindow:F2}. Time: {(Stopwatch.GetTimestamp() - this.time) * 1000 / Stopwatch.Frequency}");

        if(congestionSemaphore.CurrentCount < 1)
            congestionSemaphore.Release();

        foreach(uint number in lostPackets)
            await PacketLostAsync(number);

        if(writeAck) {
            WriteAck(packetWriter, true);

            await connection.SendAsync(packetWriter);
        }

        if(connection.writeMaxStreams) {
            connection.writeMaxStreams = false;

            WriteMaxStreams(packetWriter);

            await connection.SendAsync(packetWriter);
        }

        Task PacketLostAsync(uint number) {
            string stage = null;

            if(connection.initialStage == this)
                stage = "Initial";
            else if(connection.handshakeStage == this)
                stage = "Handshake";
            else if(connection.applicationStage == this)
                stage = "Application";

            bool exists;
            PacketInfo packet;

            lock(packets)
                exists = packets.Remove(number, out packet);

            if(connection.debugLogging)
                Console.WriteLine($"{connection.number} {stage}: Packet lost: {number} that {(exists ? "exists" : "doesn't exists")}");

            if(packet.Type == PacketInfoType.Stream)
                return connection.StreamPacketLostAsync(number, packet.StreamId).AsTask();

            if(packet.Type == PacketInfoType.Crypto)
                WriteCrypto(packetWriter, packet.Offset, packet.Length, packet.Token);
            else if(packet.Type == PacketInfoType.HandshakeDone)
                WriteHandshakeDone(packetWriter);
            else if(packet.Type == PacketInfoType.MaxStreams)
                WriteMaxStreams(packetWriter);
            
            writeAck = true;

            return connection.SendAsync(packetWriter).AsTask();
        }
    }

    public async Task WaitForCongestion(int length) {
        //Console.WriteLine($"Waiting {bytesInFlight} + {length} > {congestionWindow * MaxSegmentSize}");

        while(bytesInFlight + length > congestionWindow * MaxSegmentSize)
            await congestionSemaphore.WaitAsync();

        //Console.WriteLine($"Waited");
    }

    public uint GetNextPacketNumber(bool ackEliciting) {
        uint number = Interlocked.Increment(ref nextPacketNumber);

        if(connection.debugLogging)
            Console.WriteLine($"{connection.number} {type}: Packet number {number}");

        //inFlightSemaphore.Wait();

        //inFlightPackets.Add(new(number, ackEliciting, Stopwatch.GetTimestamp()));

        //inFlightSemaphore.Release();

        //if(ackEliciting)
        //    CalculateProbeTimeout();

        return number;
    }

    public uint GetNextPacketNumber(ulong streamId) {
        uint number = GetNextPacketNumber(true);
        
        lock(packets)
            packets.Add(number, new(PacketInfoType.Stream, PacketType.OneRtt, null, streamId, 0, 0, null));

        return number;
    }

    public void AddInFlightPacket(uint number, bool ackEliciting, int length) {
        inFlightSemaphore.Wait();

        inFlightPackets.Add(new(number, ackEliciting, length, Stopwatch.GetTimestamp()));

        bytesInFlight += length;

        inFlightSemaphore.Release();

        if(ackEliciting)
            CalculateProbeTimeout();
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

        packetWriter.FrameWriter.WriteCrypto(data, offset);

        if(token is not null)
            packetWriter.FrameWriter.WritePaddingUntil(1200);
        else
            packetWriter.FrameWriter.WritePaddingUntil(20);

        uint number = GetNextPacketNumber(true);

        if(connection.debugLogging)
            Console.WriteLine($"Crypto {type}");

        PacketType packetType = type switch {
            StageType.Initial => PacketType.Initial,
            StageType.Handshake => PacketType.Handshake,
            _ => PacketType.OneRtt
        };

        lock(packets)
            packets.Add(number, new(PacketInfoType.Crypto, packetType, null, 0, offset, length, token));

        int dataLength = packetWriter.Write(packetType, number, token);

        AddInFlightPacket(number, true, dataLength);
    }

    public void WriteAck(PacketWriter packetWriter, bool force) {
        if(acks.Count < 1 || !ackEliciting && !force)
            return;

        uint[] acksArray;

        lock(acks) {
            packetWriter.FrameWriter.WriteAck(acks);

            acksArray = [..acks];
        }
        
        ackEliciting = false;

        packetWriter.FrameWriter.WritePaddingUntil(20);

        uint number = GetNextPacketNumber(false);

        PacketType packetType = type switch {
            StageType.Initial => PacketType.Initial,
            StageType.Handshake => PacketType.Handshake,
            _ => PacketType.OneRtt
        };

        lock(packets)
            packets.Add(number, new(PacketInfoType.Ack, packetType, acksArray, 0, 0, 0, null));

        packetWriter.Write(packetType, number);

        AddInFlightPacket(number, false, 0);
    }

    public void WriteMaxStreams(PacketWriter packetWriter) {
        packetWriter.FrameWriter.WriteMaxStreams(true, connection.maxBidirectionalStreams);
        packetWriter.FrameWriter.WriteMaxStreams(false, connection.maxUnidirectionalStreams);

        packetWriter.FrameWriter.WritePaddingUntil(20);

        uint number = GetNextPacketNumber(true);

        lock(packets)
            packets.Add(number, new(PacketInfoType.MaxStreams, PacketType.OneRtt, null, 0, 0, 0, null));

        int length = packetWriter.Write(PacketType.OneRtt, number);

        AddInFlightPacket(number, true, length);
    }

    public void WriteProbe(PacketWriter packetWriter) {
        if(type == StageType.Initial && latestRtt < 0) {
            WriteCrypto(packetWriter, packets[nextPacketNumber].Offset, packets[nextPacketNumber].Length, packets[nextPacketNumber].Token);

            return;
        }

        uint[] acksArray;

        if(acks.Count > 0) {
            lock(acks) {
                packetWriter.FrameWriter.WriteAck(acks);

                acksArray = [..acks];
            }
        
            ackEliciting = false;
        } else
            acksArray = [];

        packetWriter.FrameWriter.WritePing();

        packetWriter.FrameWriter.WritePaddingUntil(20);

        uint number = GetNextPacketNumber(true);

        if(connection.debugLogging)
            Console.WriteLine($"Probe {type}");

        PacketType packetType = type switch {
            StageType.Initial => PacketType.Initial,
            StageType.Handshake => PacketType.Handshake,
            _ => PacketType.OneRtt
        };

        lock(packets)
            packets.Add(number, new(PacketInfoType.Ack, packetType, acksArray, 0, 0, 0, null));

        int length = packetWriter.Write(packetType, number);

        AddInFlightPacket(number, true, length);
    }

    public void WriteHandshakeDone(PacketWriter packetWriter) {
        packetWriter.FrameWriter.WriteHandshakeDone();

        packetWriter.FrameWriter.WritePaddingUntil(20);

        uint number = GetNextPacketNumber(true);

        PacketType packetType = type switch {
            StageType.Initial => PacketType.Initial,
            StageType.Handshake => PacketType.Handshake,
            _ => PacketType.OneRtt
        };

        lock(packets)
            packets.Add(number, new(PacketInfoType.HandshakeDone, packetType, null, 0, 0, 0, null));

        int length = packetWriter.Write(packetType, number);

        AddInFlightPacket(number, true, length);
    }

    public void CalculateProbeTimeout() {
        if(!ProbeTimeoutEnabled)
            ProbeTimeout = long.MaxValue;

        if(connection.debugLogging)
            Console.WriteLine(smoothedRtt + Math.Max(rttVar * 4, Granularity) + (type == StageType.Application ? MaxAckDelay : 0));

        ProbeTimeout = (Stopwatch.GetTimestamp() * 1000 / Stopwatch.Frequency) + smoothedRtt + Math.Max(rttVar * 4, Granularity) + (type == StageType.Application ? MaxAckDelay : 0);
    }

    readonly record struct InFlightPacket(uint Number, bool AckEliciting, int Length, long SendTime);

    readonly record struct PacketInfo(PacketInfoType Type, PacketType PacketType, uint[] Acks, ulong StreamId, ulong Offset, int Length, byte[] Token);

    enum PacketInfoType {
        Ack,
        Crypto,
        Stream,
        MaxStreams,
        HandshakeDone
    }
}
