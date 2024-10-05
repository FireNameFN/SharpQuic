using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using SharpQuic.Packets;
using SharpQuic.Tls;

namespace SharpQuic;

public sealed class QuicConnection {
    readonly UdpClient client;

    readonly TlsClient tlsClient;

    internal readonly QuicPacketProtection protection;

    readonly PacketWriter initialPacketWriter = new();

    readonly PacketWriter handshakePacketWriter = new();

    readonly byte[] sourceConnectionId;

    QuicConnection(EndpointType endpointType, UdpClient client, QuicTransportParameters parameters, string[] protocols, X509Certificate2[] certificateChain = null) {
        this.client = client;
        protection = new(endpointType);
        sourceConnectionId = parameters.InitialSourceConnectionId;

        tlsClient = new(parameters, protocols, certificateChain) {
            InitialFragmentWriter = initialPacketWriter,
            HandshakeFragmentWriter = handshakePacketWriter
        };
    }

    public static async Task<QuicConnection> ConnectAsync(IPEndPoint point, string[] protocols) {
        QuicTransportParameters parameters = new() {
            InitialSourceConnectionId = new byte[8]
        };

        QuicConnection connection = new(EndpointType.Client, new(), parameters, protocols);

        connection.tlsClient.SendClientHello();

        connection.initialPacketWriter.WritePaddingUntil1200();

        InitialPacket packet = new() {
            DestinationConnectionId = [],
            SourceConnectionId = connection.sourceConnectionId,
            Token = [],
            Payload = connection.initialPacketWriter.stream.ToArray()
        };

        byte[] protectedPacket = connection.protection.Protect(packet);

        await connection.client.SendAsync(protectedPacket, point);

        UdpReceiveResult result = await connection.client.ReceiveAsync();

        MemoryStream stream = new(result.Buffer);

        packet = (InitialPacket)connection.protection.Unprotect(stream);

        PacketReader reader = new() {
            stream = new MemoryStream(packet.Payload)
        };

        Frame frame;

        do {
            frame = reader.Read();
        } while(frame.Type != FrameType.Crypto);

        connection.tlsClient.ReceiveHandshake(frame.Data);

        connection.tlsClient.DeriveHandshakeSecrets();

        connection.protection.GenerateKeys(connection.tlsClient.clientHandshakeSecret, connection.tlsClient.serverHandshakeSecret);

        return connection;
    }

    public static async Task<QuicConnection> ListenAsync(IPEndPoint point, string[] protocols) {
        QuicTransportParameters parameters = new() {
            InitialSourceConnectionId = new byte[8]
        };

        QuicConnection connection = new(EndpointType.Server, new(point), parameters, protocols);

        UdpReceiveResult result = await connection.client.ReceiveAsync();

        MemoryStream stream = new(result.Buffer);

        InitialPacket packet = (InitialPacket)connection.protection.Unprotect(stream);

        PacketReader reader = new() {
            stream = new MemoryStream(packet.Payload)
        };

        Frame frame = reader.Read();

        connection.tlsClient.ReceiveHandshake(frame.Data);

        connection.tlsClient.SendServerHello();

        packet = new() {
            DestinationConnectionId = packet.SourceConnectionId,
            SourceConnectionId = packet.DestinationConnectionId,
            Token = [],
            Payload = connection.initialPacketWriter.stream.ToArray()
        };

        byte[] protectedPacket = connection.protection.Protect(packet);

        await connection.client.SendAsync(protectedPacket, result.RemoteEndPoint);

        connection.tlsClient.DeriveHandshakeSecrets();

        connection.protection.GenerateKeys(connection.tlsClient.clientHandshakeSecret, connection.tlsClient.serverHandshakeSecret);

        /*connection.tlsClient.SendServerHandshake();

        packet = new() {
            DestinationConnectionId = packet.SourceConnectionId,
            SourceConnectionId = packet.DestinationConnectionId,
            Token = [],
            Payload = connection.handshakePacketWriter.stream.ToArray()
        };

        protectedPacket = connection.protection.Protect(packet);

        await connection.client.SendAsync(protectedPacket, result.RemoteEndPoint);

        result = await connection.client.ReceiveAsync();

        stream = new(result.Buffer);

        connection.protection.Unprotect(stream);

        result = await connection.client.ReceiveAsync();

        stream = new(result.Buffer);

        HandshakePacket handshakePacket = (HandshakePacket)connection.protection.Unprotect(stream);

        reader = new() {
            stream = new MemoryStream(handshakePacket.Payload)
        };

        do {
            frame = reader.Read();
        } while(frame.Type != FrameType.Crypto);

        connection.tlsClient.ReceiveHandshake(frame.Data);

        connection.tlsClient.DeriveApplicationSecrets();

        connection.protection.GenerateKeys(connection.tlsClient.clientApplicationSecret, connection.tlsClient.serverApplicationSecret);*/

        return connection;
    }
}
