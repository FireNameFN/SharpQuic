using System.IO;

namespace SharpQuic.Packets;

public sealed class InitialPacket : LongHeaderPacket {
    public int? TokenLengthLength { get; set; }

    public byte[] Token { get; set; }

    public InitialPacket() {
        PacketType = 0b11000000;
    }

    public void EncodeToken(Stream stream) {
        Serializer.WriteVariableLength(stream, (ulong)Token.Length, TokenLengthLength ?? 0);

        stream.Write(Token);
    }
}
