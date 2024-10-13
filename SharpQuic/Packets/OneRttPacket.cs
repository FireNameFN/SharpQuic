namespace SharpQuic.Packets;

public sealed class OneRttPacket : Packet {
    public bool Spin { get; set; }

    public bool KeyPhase { get; set; }

    public OneRttPacket() {
        PacketType = PacketType.OneRtt;
    }
}
