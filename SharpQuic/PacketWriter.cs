using System;
using System.Collections.Generic;
using System.IO;
using SharpQuic.Packets;

namespace SharpQuic;

public sealed class PacketWriter {
    readonly QuicConnection connection;

    readonly MemoryStream stream = new();

    uint nextPacketNumber; // TODO

    internal PacketWriter(QuicConnection connection) {
        this.connection = connection;
    }

    public void Write(PacketType type, byte[] payload, byte[] token = null) {
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
        packet.Payload = payload;

        stream.Write(connection.protection.Protect(packet, connection.initialStage.KeySet, connection.handshakeStage?.KeySet, connection.applicationStage?.KeySet));
    }

    public byte[] ToDatagram() {
        byte[] datagram = stream.ToArray();

        stream.SetLength(0);

        return datagram;
    }

    /*public void CopyTo(Stream stream) {
        this.stream.Position = 0;
        this.stream.CopyTo(stream);
        //this.stream.Position = 0;
        this.stream.SetLength(0);
    }*/
}
