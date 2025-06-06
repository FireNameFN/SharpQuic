using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SharpQuic.Tls;
using Xunit;

namespace SharpQuic.Tests;

public class TlsClientTests {
    [Fact]
    public void TlsClientTest() {
        CertificateRequest request = new("cn=TlsClientTest CA", RSA.Create(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        
        X509Certificate2 certificate = request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));

        TlsClient client = new(new() { InitialSourceConnectionId = [] }, ["test"], chainPolicy: new() {
            TrustMode = X509ChainTrustMode.CustomRootTrust,
            RevocationMode = X509RevocationMode.NoCheck,
            CustomTrustStore = {
                certificate
            }
        });

        TlsClient server = new(new() { InitialSourceConnectionId = [] }, ["test"], [certificate]);

        server.TryReceiveHandshake(new MemoryStream(client.SendClientHello()));

        MemoryStream stream = new(server.SendServerHello());

        while(stream.Position < stream.Length)
            client.TryReceiveHandshake(stream);

        Assert.True(client.key.SequenceEqual(server.key));

        client.DeriveHandshakeSecrets();
        server.DeriveHandshakeSecrets();

        Assert.True(client.clientHandshakeSecret.SequenceEqual(server.clientHandshakeSecret));
        Assert.True(client.serverHandshakeSecret.SequenceEqual(server.serverHandshakeSecret));

        stream = new(server.SendServerHandshake());

        while(stream.Position < stream.Length)
            client.TryReceiveHandshake(stream);

        client.DeriveApplicationSecrets();
        server.DeriveApplicationSecrets();

        Assert.True(client.clientApplicationSecret.SequenceEqual(server.clientApplicationSecret));
        Assert.True(client.serverApplicationSecret.SequenceEqual(server.serverApplicationSecret));
    }
}
