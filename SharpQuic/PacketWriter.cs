using System;
using System.IO;
using SharpQuic.Packets;

namespace SharpQuic;

public sealed class PacketWriter {
    readonly QuicConnection connection;

    readonly MemoryStream stream = new();

    readonly PacketType type;

    uint nextPacketNumber;

    public FrameWriter FrameWriter { get; } = new();

    internal PacketWriter(QuicConnection connection, PacketType type) {
        this.connection = connection;
        this.type = type;
    }

    public void Write(byte[] token = null) {
        LongHeaderPacket packet = type switch {
            PacketType.Initial => new InitialPacket() { Token = token ?? [] },
            PacketType.Handshake => new HandshakePacket(),
            _ => throw new NotImplementedException()
        };

        packet.SourceConnectionId = connection.sourceConnectionId;
        packet.DestinationConnectionId = connection.destinationConnectionId;
        packet.PacketNumber = nextPacketNumber++;
        packet.Payload = FrameWriter.ToPayload();

        stream.Write(connection.protection.Protect(packet));
    }

    public void CopyTo(Stream stream) {
        this.stream.Position = 0;
        this.stream.CopyTo(stream);
        //this.stream.Position = 0;
        this.stream.SetLength(0);
    }
}
