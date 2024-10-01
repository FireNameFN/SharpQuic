namespace SharpQuic.Packets;

public sealed class HandshakePacket : LongHeaderPacket {
    public HandshakePacket() {
        PacketType = 0b11110000;
    }
}
