namespace SharpQuic.Packets;

public abstract class LongHeaderPacket : Packet {
    public byte[] SourceConnectionId { get; set; }
}
