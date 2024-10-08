namespace SharpQuic.Packets;

public class LongHeaderPacket : Packet {
    public byte[] SourceConnectionId { get; set; }
}
