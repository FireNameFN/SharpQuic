using System;
using System.IO;
using SharpQuic.Packets;

namespace SharpQuic;

public sealed class PacketWriter {
    readonly QuicConnection connection;

    readonly MemoryStream stream = new();

    public FrameWriter FrameWriter { get; } = new();

    public int Length => (int)stream.Length;

    internal PacketWriter(QuicConnection connection) {
        this.connection = connection;
    }

    public void Write(PacketType type, uint packetNumber, byte[] token = null) {
        Packet packet = type switch {
            PacketType.Initial => new InitialPacket() { Token = token ?? [] },
            PacketType.Handshake => new HandshakePacket(),
            PacketType.OneRtt => new OneRttPacket(),
            _ => throw new NotImplementedException()
        };

        if(packet is LongHeaderPacket longHeaderPacket)
            longHeaderPacket.SourceConnectionId = connection.sourceConnectionId;
        
        packet.DestinationConnectionId = connection.destinationConnectionId;
        packet.PacketNumber = packetNumber;
        packet.Payload = FrameWriter.ToPayload();

        stream.Write(connection.protection.Protect(packet, connection.initialStage?.KeySet, connection.handshakeStage?.KeySet, connection.applicationStage?.KeySet));
    }

    public Memory<byte> ToDatagram() {
        Memory<byte> datagram = stream.GetBuffer().AsMemory()[..(int)stream.Length];

        stream.SetLength(0);

        return datagram;
    }
}
