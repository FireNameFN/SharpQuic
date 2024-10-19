using System;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using NUnit.Framework;

namespace SharpQuic.Tests;

[TestFixture]
public class QuicConnectionTests {
    [Test, Explicit]
    public async Task QuicConnectionTestAsync() {
        QuicConnection client = null;

        TaskCompletionSource source = new();

        _ = Task.Run(async () => {
            try {
                client = await QuicConnection.ConnectAsync(new() {
                    Point = IPEndPoint.Parse("127.0.0.1:50000"),
                    Protocols = ["test"]
                });

                source.SetResult();
            } catch(Exception e) {
                source.SetException(e);
            }
        });

        CertificateRequest request = new("cn=Test CA", RSA.Create(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        //CertificateRequest request = new("cn=Test CA", ECDsa.Create(), HashAlgorithmName.SHA256);

        X509Certificate2 certificate = request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));

        QuicConnection server = await QuicConnection.ListenAsync(new() {
            Point = IPEndPoint.Parse("0.0.0.0:50000"),
            Protocols = ["test"],
            CertificateChain = [certificate]
        });

        await source.Task;

        Assert.That(client.applicationStage.KeySet.SourceKey.AsSpan().SequenceEqual(server.applicationStage.KeySet.DestinationKey));
        Assert.That(client.applicationStage.KeySet.SourceIv.AsSpan().SequenceEqual(server.applicationStage.KeySet.DestinationIv));
        Assert.That(client.applicationStage.KeySet.SourceHp.AsSpan().SequenceEqual(server.applicationStage.KeySet.DestinationHp));
    }

    [Test, Explicit]
    public async Task ConnectToExternalServerTestAsync() {
        await QuicConnection.ConnectAsync(new() {
            Point = IPEndPoint.Parse("127.0.0.1:853"),
            Protocols = ["doq"]
        });
    }

    [Test, Explicit]
    public async Task ListenExternalClientTestAsync() {
        CertificateRequest request = new("cn=Test CA", RSA.Create(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        SubjectAlternativeNameBuilder builder = new();

        builder.AddIpAddress(IPAddress.Parse("127.0.0.1"));

        request.CertificateExtensions.Add(builder.Build());

        X509Certificate2 certificate = request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));

        await QuicConnection.ListenAsync(new() {
            Point = IPEndPoint.Parse("127.0.0.1:50000"),
            Protocols = ["test"],
            CertificateChain = [certificate]
        });
    }
}
