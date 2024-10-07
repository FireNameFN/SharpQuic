namespace SharpQuic.Packets;

public sealed class HandshakePacket : LongHeaderPacket {
    public HandshakePacket() {
        PacketType = PacketType.Handshake;
    }
}
