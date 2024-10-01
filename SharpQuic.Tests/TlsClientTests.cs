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
            InitialPacketWriter = new()
        };

        client.SendClientHello();

        TlsClient server = new() {
            InitialPacketWriter = new()
        };

        client.InitialPacketWriter.stream.Position = 0;

        PacketReader reader = new() {
            stream = new MemoryStream(client.InitialPacketWriter.stream.ToArray())
        };

        server.ReceiveHandshake(reader.Read().Data);

        server.SendServerHello();

        server.InitialPacketWriter.stream.Position = 0;

        reader.stream = new MemoryStream(server.InitialPacketWriter.stream.ToArray());

        client.ReceiveHandshake(reader.Read().Data);

        Assert.That(client.key.SequenceEqual(server.key));

        client.DeriveSecrets();
        server.DeriveSecrets();

        Assert.That(client.clientHandshakeSecret.SequenceEqual(server.clientHandshakeSecret));
        Assert.That(client.serverHandshakeSecret.SequenceEqual(server.serverHandshakeSecret));
    }
}
