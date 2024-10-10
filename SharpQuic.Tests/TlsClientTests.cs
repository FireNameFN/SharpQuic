using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using NUnit.Framework;
using SharpQuic.Tls;
using SharpQuic.Tls.Enums;

namespace SharpQuic.Tests;

[TestFixture]
public class TlsClientTests {
    [Test]
    public void TlsClientTest() {
        CertificateRequest request = new("cn=TlsClientTest CA", RSA.Create(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        
        X509Certificate2 certificate = request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));

        FrameWriter clientInitialPacketWriter = new();
        FrameWriter clientHandshakePacketWriter = new();
        FrameWriter serverInitialPacketWriter = new();
        FrameWriter serverHandshakePacketWriter = new();

        TlsClient client = new(new() { InitialSourceConnectionId = [] }, ["test"]) {
            InitialFragmentWriter = clientInitialPacketWriter,
            HandshakeFragmentWriter = clientHandshakePacketWriter
        };

        client.SendClientHello();

        TlsClient server = new(new() { InitialSourceConnectionId = [] }, ["test"], [certificate]) {
            InitialFragmentWriter = serverInitialPacketWriter,
            HandshakeFragmentWriter = serverHandshakePacketWriter
        };

        FrameReader reader = new() {
            stream = new MemoryStream(clientInitialPacketWriter.ToPayload())
        };

        byte[] data = reader.Read().Data;

        server.ReceiveHandshake(TlsClient.ReadHandshakeHeader(data[..4]).Type, data[4..]);

        server.SendServerHello();

        reader.stream = new MemoryStream(serverInitialPacketWriter.ToPayload());

        MemoryStream stream = new(reader.Read().Data);

        while(stream.Position < stream.Length) {
            data = new byte[4];

            stream.ReadExactly(data);

            (HandshakeType type, int length) = TlsClient.ReadHandshakeHeader(data);

            data = new byte[length];

            stream.ReadExactly(data);

            client.ReceiveHandshake(type, data);
        }

        Assert.That(client.key.SequenceEqual(server.key));

        client.DeriveHandshakeSecrets();
        server.DeriveHandshakeSecrets();

        Assert.That(client.clientHandshakeSecret.SequenceEqual(server.clientHandshakeSecret));
        Assert.That(client.serverHandshakeSecret.SequenceEqual(server.serverHandshakeSecret));

        server.SendServerHandshake();

        reader.stream = new MemoryStream(serverHandshakePacketWriter.ToPayload());

        stream = new(reader.Read().Data);

        while(stream.Position < stream.Length) {
            data = new byte[4];

            stream.ReadExactly(data);

            (HandshakeType type, int length) = TlsClient.ReadHandshakeHeader(data);

            data = new byte[length];

            stream.ReadExactly(data);

            client.ReceiveHandshake(type, data);
        }

        client.DeriveApplicationSecrets();
        server.DeriveApplicationSecrets();

        Assert.That(client.clientApplicationSecret.SequenceEqual(server.clientApplicationSecret));
        Assert.That(client.serverApplicationSecret.SequenceEqual(server.serverApplicationSecret));
    }
}
