using System.IO;

namespace SharpQuic.Packets;

public sealed class InitialPacket : LongHeaderPacket {
    public byte[] Token { get; set; }

    public InitialPacket() {
        PacketType = 0b11000000;
    }

    protected override void EncodeToken(Stream stream) {
        Serializer.WriteVariableLength(stream, (ulong)Token.Length);

        stream.Write(Token);
    }
}
