using System.IO;

namespace SharpQuic.Packets;

public class Packet {
    public PacketType PacketType { get; protected set; }

    public byte[] DestinationConnectionId { get; set; }

    public int? PacketNumberLength { get; set; }

    public uint PacketNumber { get; set; }

    public int? LengthLength { get; set; }

    public byte[] Payload { get; set; }
    
    public byte[] EncodeUnprotectedHeader() {
        MemoryStream stream = new();

        Serializer.WriteByte(stream, GetUnprotectedFirstByte());

        stream.Write(EncodePublicHeader());

        Serializer.WriteWithLength(stream, PacketNumber, GetPacketNumberLength());

        return stream.ToArray();
    }

    public byte GetUnprotectedFirstByte() {
        return (byte)((byte)PacketType | GetPacketNumberLength() - 1);
    }

    public byte[] EncodePublicHeader() {
        MemoryStream stream = new();

        if(this is LongHeaderPacket)
            Serializer.WriteUInt32(stream, 1);

        Serializer.WriteByte(stream, (byte)DestinationConnectionId.Length);

        stream.Write(DestinationConnectionId);

        if(this is LongHeaderPacket longHeaderPacket) {
            Serializer.WriteByte(stream, (byte)longHeaderPacket.SourceConnectionId.Length);

            stream.Write(longHeaderPacket.SourceConnectionId);

            if(this is InitialPacket initialPacket)
                initialPacket.EncodeToken(stream);
        }

        Serializer.WriteVariableLength(stream, (ulong)(GetPacketNumberLength() + Payload.Length + 16), LengthLength ?? 0);

        return stream.ToArray();
    }

    public int GetPacketNumberLength() {
        return PacketNumberLength ?? Serializer.GetLength(PacketNumber);
    }
}
