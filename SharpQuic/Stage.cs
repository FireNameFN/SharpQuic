using System.Collections.Generic;

namespace SharpQuic;

public sealed class Stage {
    public FrameWriter FrameWriter { get; } = new();

    public KeySet KeySet { get; init; }

    public HashSet<uint> Received { get; } = [];

    readonly SortedSet<uint> acks = [];

    bool ackEliciting;

    uint nextPacketNumber;

    public void Ack(uint packetNumber, bool ackEliciting) {
        acks.Add(packetNumber);

        this.ackEliciting |= ackEliciting;
    }

    public void Write(PacketWriter packetWriter, PacketType type, byte[] token = null) {
        if(!FrameWriter.HasPayload && !ackEliciting)
            return;

        if(acks.Count > 0) {
            FrameWriter.WriteAck(acks);

            acks.Clear();
        }

        FrameWriter.WritePaddingUntil(20);

        packetWriter.Write(type, nextPacketNumber++, FrameWriter.ToPayload(), token);
    }
}
