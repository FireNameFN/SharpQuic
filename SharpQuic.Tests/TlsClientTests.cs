using System;
using System.IO;
using System.Linq;
using NUnit.Framework;
using SharpQuic.Tls;

namespace SharpQuic.Tests;

[TestFixture]
public class TlsClientTests {
    [Test]
    public void TlsClientTest() {
        PacketWriter clientInitialPacketWriter = new();
        PacketWriter clientHandshakePacketWriter = new();
        PacketWriter serverInitialPacketWriter = new();
        PacketWriter serverHandshakePacketWriter = new();

        TlsClient client = new() {
            InitialFragmentWriter = clientInitialPacketWriter,
            HandshakeFragmentWriter = clientHandshakePacketWriter
        };

        client.SendClientHello();

        TlsClient server = new() {
            InitialFragmentWriter = serverInitialPacketWriter,
            HandshakeFragmentWriter = serverHandshakePacketWriter
        };

        PacketReader reader = new() {
            stream = new MemoryStream(clientInitialPacketWriter.stream.ToArray())
        };

        server.ReceiveHandshake(reader.Read().Data);

        server.SendServerHello();

        reader.stream = new MemoryStream(serverInitialPacketWriter.stream.ToArray());

        client.ReceiveHandshake(reader.Read().Data);

        Assert.That(client.key.SequenceEqual(server.key));

        client.DeriveHandshakeSecrets();
        server.DeriveHandshakeSecrets();

        Assert.That(client.clientHandshakeSecret.SequenceEqual(server.clientHandshakeSecret));
        Assert.That(client.serverHandshakeSecret.SequenceEqual(server.serverHandshakeSecret));

        server.SendServerHandshake();

        reader.stream = new MemoryStream(serverHandshakePacketWriter.stream.ToArray());

        client.ReceiveHandshake(reader.Read().Data);

        client.DeriveApplicationSecrets();
        server.DeriveApplicationSecrets();

        Assert.That(client.clientApplicationSecret.SequenceEqual(server.clientApplicationSecret));
        Assert.That(client.serverApplicationSecret.SequenceEqual(server.serverApplicationSecret));
    }
}
