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
        TlsClient client = new() {
            InitialPacketWriter = new(),
            HandshakePacketWriter = new()
        };

        client.SendClientHello();

        TlsClient server = new() {
            InitialPacketWriter = new(),
            HandshakePacketWriter = new()
        };

        PacketReader reader = new() {
            stream = new MemoryStream(client.InitialPacketWriter.stream.ToArray())
        };

        server.ReceiveHandshake(reader.Read().Data);

        server.SendServerHello();

        reader.stream = new MemoryStream(server.InitialPacketWriter.stream.ToArray());

        client.ReceiveHandshake(reader.Read().Data);

        Assert.That(client.key.SequenceEqual(server.key));

        client.DeriveHandshakeSecrets();
        server.DeriveHandshakeSecrets();

        Assert.That(client.clientHandshakeSecret.SequenceEqual(server.clientHandshakeSecret));
        Assert.That(client.serverHandshakeSecret.SequenceEqual(server.serverHandshakeSecret));

        server.SendServerHandshake();

        reader.stream = new MemoryStream(server.HandshakePacketWriter.stream.ToArray());

        client.ReceiveHandshake(reader.Read().Data);

        client.DeriveApplicationSecrets();
        server.DeriveApplicationSecrets();

        Assert.That(client.clientApplicationSecret.SequenceEqual(server.clientApplicationSecret));
        Assert.That(client.serverApplicationSecret.SequenceEqual(server.serverApplicationSecret));
    }
}
