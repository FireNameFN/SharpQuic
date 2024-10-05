using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using NUnit.Framework;
using SharpQuic.Tls;

namespace SharpQuic.Tests;

[TestFixture]
public class TlsClientTests {
    [Test]
    public void TlsClientTest() {
        CertificateRequest request = new("cn=TlsClientTest CA", RSA.Create(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        
        X509Certificate2 certificate = request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));

        PacketWriter clientInitialPacketWriter = new();
        PacketWriter clientHandshakePacketWriter = new();
        PacketWriter serverInitialPacketWriter = new();
        PacketWriter serverHandshakePacketWriter = new();

        TlsClient client = new(new(), ["test"]) {
            InitialFragmentWriter = clientInitialPacketWriter,
            HandshakeFragmentWriter = clientHandshakePacketWriter
        };

        client.SendClientHello();

        TlsClient server = new(new(), ["test"], [certificate]) {
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
