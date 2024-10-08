namespace SharpQuic.Packets;

public sealed class OneRttPacket : Packet {
    public OneRttPacket() {
        PacketType = PacketType.OneRtt;
    }
}
