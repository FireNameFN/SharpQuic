using System.IO;

namespace SharpQuic.Packets;

public class LongHeaderPacket {
    public byte PacketType { get; protected set; }

    public byte[] DestinationConnectionId { get; set; }

    public byte[] SourceConnectionId { get; set; }

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
        return (byte)(PacketType | GetPacketNumberLength() - 1);
    }

    public byte[] EncodePublicHeader() {
        MemoryStream stream = new();

        Serializer.WriteUInt32(stream, 1);

        Serializer.WriteByte(stream, (byte)DestinationConnectionId.Length);

        stream.Write(DestinationConnectionId);

        Serializer.WriteByte(stream, (byte)SourceConnectionId.Length);

        stream.Write(SourceConnectionId);

        EncodeToken(stream);

        Serializer.WriteVariableLength(stream, (ulong)(GetPacketNumberLength() + Payload.Length + 16));

        return stream.ToArray();
    }

    protected virtual void EncodeToken(Stream stream) { }

    public int GetPacketNumberLength() {
        return PacketNumberLength ?? Serializer.GetLength(PacketNumber);
    }
}
