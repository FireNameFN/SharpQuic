using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using NUnit.Framework;
using SharpQuic.Frames;
using SharpQuic.Tls;

namespace SharpQuic.Tests;

[TestFixture]
public class TlsClientTests {
    [Test]
    public void TlsClientTest() {
        CertificateRequest request = new("cn=TlsClientTest CA", RSA.Create(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        
        X509Certificate2 certificate = request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));

        TlsClient client = new(new() { InitialSourceConnectionId = [] }, ["test"]);

        TlsClient server = new(new() { InitialSourceConnectionId = [] }, ["test"], [certificate]);

        server.TryReceiveHandshake(new MemoryStream(client.SendClientHello()));

        MemoryStream stream = new(server.SendServerHello());

        while(stream.Position < stream.Length)
            client.TryReceiveHandshake(stream);

        Assert.That(client.key.SequenceEqual(server.key));

        client.DeriveHandshakeSecrets();
        server.DeriveHandshakeSecrets();

        Assert.That(client.clientHandshakeSecret.SequenceEqual(server.clientHandshakeSecret));
        Assert.That(client.serverHandshakeSecret.SequenceEqual(server.serverHandshakeSecret));

        stream = new(server.SendServerHandshake());

        while(stream.Position < stream.Length)
            client.TryReceiveHandshake(stream);

        client.DeriveApplicationSecrets();
        server.DeriveApplicationSecrets();

        Assert.That(client.clientApplicationSecret.SequenceEqual(server.clientApplicationSecret));
        Assert.That(client.serverApplicationSecret.SequenceEqual(server.serverApplicationSecret));
    }
}
