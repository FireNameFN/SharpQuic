using System.IO;

namespace SharpQuic.Packets;

public sealed class RetryPacket : LongHeaderPacket {
    public int? TokenLengthLength { get; set; }

    public byte[] Token { get; set; }

    public RetryPacket() {
        PacketType = PacketType.Retry;
    }

    /*public void EncodeToken(Stream stream) {
        Serializer.WriteVariableLength(stream, (ulong)Token.Length, TokenLengthLength ?? 0);

        stream.Write(Token);
    }*/
}
