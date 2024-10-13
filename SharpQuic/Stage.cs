using System.Collections.Generic;

namespace SharpQuic;

public sealed class Stage {
    public FrameWriter FrameWriter { get; } = new();

    public KeySet KeySet { get; init; }

    public HashSet<uint> Received { get; } = [];

    uint nextPacketNumber;

    public void Write(PacketWriter packetWriter, PacketType type, byte[] token = null) {
        if(FrameWriter.HasPayload)
            packetWriter.Write(type, nextPacketNumber++, FrameWriter.ToPayload(), token);
    }
}
