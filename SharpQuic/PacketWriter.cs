using System;
using System.Collections.Generic;
using System.IO;
using SharpQuic.Packets;

namespace SharpQuic;

public sealed class PacketWriter {
    readonly QuicConnection connection;

    readonly MemoryStream stream = new();

    readonly PacketType type;

    uint nextPacketNumber;

    public FrameWriter FrameWriter { get; } = new();

    readonly SortedSet<uint> acks = [];

    internal PacketWriter(QuicConnection connection, PacketType type) {
        this.connection = connection;
        this.type = type;
    }

    public void Ack(uint packetNumber) {
        acks.Add(packetNumber);
    }

    public void Write(byte[] token = null) {
        if(acks.Count > 0) {
            FrameWriter.WriteAck(acks);
            acks.Clear();
        }

        Packet packet = type switch {
            PacketType.Initial => new InitialPacket() { Token = token ?? [] },
            PacketType.Handshake => new HandshakePacket(),
            PacketType.OneRtt => new OneRttPacket(),
            _ => throw new NotImplementedException()
        };

        if(packet is LongHeaderPacket longHeaderPacket)
            longHeaderPacket.SourceConnectionId = connection.sourceConnectionId;
            
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
