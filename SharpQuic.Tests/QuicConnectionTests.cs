using System;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using NUnit.Framework;

namespace SharpQuic.Tests;

[TestFixture]
public class QuicConnectionTests {
    [Test]
    public async Task QuicConnectionTest() {
        QuicConnection client = null;

        TaskCompletionSource source = new();

        _ = Task.Run(async () => {
            client = await QuicConnection.ConnectAsync(new() {
                Point = IPEndPoint.Parse("127.0.0.1:50000"),
                Protocols = ["test"]
            });

            source.SetResult();
        });

        CertificateRequest request = new CertificateRequest("cn=Test CA", RSA.Create(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        //CertificateRequest request = new CertificateRequest("cn=Test CA", ECDsa.Create(), HashAlgorithmName.SHA256);

        X509Certificate2 certificate = request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));

        QuicConnection server = await QuicConnection.ListenAsync(new() {
            Point = IPEndPoint.Parse("0.0.0.0:50000"),
            Protocols = ["test"],
            CertificateChain = [certificate]
        });

        await source.Task;

        Assert.That(client.protection.sourceKey.SequenceEqual(server.protection.destinationKey));
        Assert.That(client.protection.sourceIv.SequenceEqual(server.protection.destinationIv));
        Assert.That(client.protection.sourceHp.SequenceEqual(server.protection.destinationHp));
    }

    [Test, Explicit]
    public async Task ConnectToDoQServer() {
        IPHostEntry entry = await Dns.GetHostEntryAsync("dns.adguard-dns.com");
        
        await QuicConnection.ConnectAsync(new() {
            Point = new(entry.AddressList[0], 853),
            Protocols = ["doq"]
        });
    }

    [Test, Explicit]
    public async Task ConnectToExternalServer() {
        await QuicConnection.ConnectAsync(new() {
            Point = IPEndPoint.Parse("127.0.0.1:853"),
            Protocols = ["doq"]
        });
    }

    [Test, Explicit]
    public async Task ListenExternalClient() {
        await QuicConnection.ListenAsync(new() {
            Point = IPEndPoint.Parse("127.0.0.1:50000"),
            Protocols = ["test"]
        });
    }
}
