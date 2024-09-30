using System.IO;

namespace SharpQuic.Packets;

public sealed class InitialPacket {
    public byte[] DestinationConnectionId { get; set; }

    public byte[] SourceConnectionId { get; set; }

    public byte[] Token { get; set; }

    public int? PacketNumberLength { get; set; }

    public uint PacketNumber { get; set; }

    public byte[] Payload { get; set; }

    public byte[] EncodeUnprotectedHeader() {
        MemoryStream stream = new();

        Serializer.WriteByte(stream, GetUnprotectedFirstByte());

        stream.Write(EncodePublicHeader());

        Serializer.WriteWithLength(stream, PacketNumber, GetPacketNumberLength());

        return stream.ToArray();
    }

    public byte GetUnprotectedFirstByte() {
        return (byte)(0b11000000 | GetPacketNumberLength() - 1);
    }

    public byte[] EncodePublicHeader() {
        MemoryStream stream = new();

        Serializer.WriteUInt32(stream, 1);

        Serializer.WriteByte(stream, (byte)DestinationConnectionId.Length);

        stream.Write(DestinationConnectionId);

        Serializer.WriteByte(stream, (byte)SourceConnectionId.Length);

        stream.Write(SourceConnectionId);

        Serializer.WriteVariableLength(stream, (ulong)Token.Length);

        stream.Write(Token);

        Serializer.WriteVariableLength(stream, (ulong)(GetPacketNumberLength() + Payload.Length + 16));

        return stream.ToArray();
    }

    public int GetPacketNumberLength() {
        return PacketNumberLength ?? Serializer.GetLength(PacketNumber);
    }
}
