using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using SharpQuic.Packets;
using SharpQuic.Tls;

namespace SharpQuic;

public sealed class QuicConnection {
    UdpClient client;

    readonly TlsClient tlsClient = new();

    internal readonly QuicPacketProtection protection;

    readonly PacketWriter initialPacketWriter = new();

    readonly PacketWriter handshakePacketWriter = new();

    QuicConnection(EndpointType endpointType, UdpClient client) {
        this.client = client;
        protection = new(endpointType);

        tlsClient.InitialPacketWriter = initialPacketWriter;
        tlsClient.HandshakePacketWriter = handshakePacketWriter;
    }

    public static async Task<QuicConnection> ConnectAsync(IPEndPoint point) {
        QuicConnection connection = new(EndpointType.Client, new());

        connection.tlsClient.SendClientHello();

        InitialPacket packet = new() {
            DestinationConnectionId = [],
            SourceConnectionId = [],
            Token = [],
            Payload = connection.initialPacketWriter.stream.ToArray()
        };

        byte[] protectedPacket = connection.protection.Protect(packet);

        await connection.client.SendAsync(protectedPacket, point);

        UdpReceiveResult result = await connection.client.ReceiveAsync();

        packet = (InitialPacket)connection.protection.Unprotect(result.Buffer);

        PacketReader reader = new() {
            stream = new MemoryStream(packet.Payload)
        };

        Frame frame = reader.Read();

        connection.tlsClient.ReceiveHandshake(frame.Data);

        connection.tlsClient.DeriveHandshakeSecrets();

        connection.protection.GenerateKeys(connection.tlsClient.clientHandshakeSecret, connection.tlsClient.serverHandshakeSecret);

        return connection;
    }

    public static async Task<QuicConnection> ListenAsync(IPEndPoint point) {
        QuicConnection connection = new(EndpointType.Server, new(point));

        UdpReceiveResult result = await connection.client.ReceiveAsync();

        InitialPacket packet = (InitialPacket)connection.protection.Unprotect(result.Buffer);

        PacketReader reader = new() {
            stream = new MemoryStream(packet.Payload)
        };

        Frame frame = reader.Read();

        connection.tlsClient.ReceiveHandshake(frame.Data);

        connection.tlsClient.SendServerHello();

        packet = new() {
            DestinationConnectionId = [],
            SourceConnectionId = [],
            Token = [],
            Payload = connection.initialPacketWriter.stream.ToArray()
        };

        byte[] protectedPacket = connection.protection.Protect(packet);

        await connection.client.SendAsync(protectedPacket, result.RemoteEndPoint);

        connection.tlsClient.DeriveHandshakeSecrets();

        connection.protection.GenerateKeys(connection.tlsClient.clientHandshakeSecret, connection.tlsClient.serverHandshakeSecret);

        return connection;
    }
}
