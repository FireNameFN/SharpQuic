using System.IO;

namespace SharpQuic.Packets;

public abstract class Packet {
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
        int firstByte = (byte)PacketType | GetPacketNumberLength() - 1;

        if(this is OneRttPacket oneRttPacket)
            firstByte |= (oneRttPacket.Spin ? 0b00100000 : 0) | (oneRttPacket.KeyPhase ? 0b00000100 : 0);

        return (byte)firstByte;
    }

    public byte[] EncodePublicHeader() {
        MemoryStream stream = new();

        if(this is LongHeaderPacket) {
            Serializer.WriteUInt32(stream, 1);

            Serializer.WriteByte(stream, (byte)DestinationConnectionId.Length);
        }

        stream.Write(DestinationConnectionId);

        if(this is LongHeaderPacket longHeaderPacket) {
            Serializer.WriteByte(stream, (byte)longHeaderPacket.SourceConnectionId.Length);

            stream.Write(longHeaderPacket.SourceConnectionId);

            if(this is InitialPacket initialPacket)
                initialPacket.EncodeToken(stream);
                
            Serializer.WriteVariableLength(stream, (ulong)(GetPacketNumberLength() + Payload.Length + 16), LengthLength ?? 0);
        }

        return stream.ToArray();
    }

    public int GetPacketNumberLength() {
        return PacketNumberLength ?? Serializer.GetLength(PacketNumber);
    }
}
