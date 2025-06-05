using System;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using NUnit.Framework;

namespace SharpQuic.Tests;

[TestFixture]
public class QuicConnectionCloseTests {
    [Test, Explicit]
    public async Task IdleTimeoutTestAsync() {
        CancellationTokenSource timeoutSource = new(5000);

        QuicConnection client = null;

        TaskCompletionSource source = new();

        CertificateRequest request = new("cn=Test CA", RSA.Create(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        //CertificateRequest request = new("cn=Test CA", ECDsa.Create(), HashAlgorithmName.SHA256);

        X509Certificate2 certificate = request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));

        _ = Task.Run(async () => {
            try {
                client = await QuicConnection.ConnectAsync(new() {
                    RemotePoint = IPEndPoint.Parse("127.0.0.1:50000"),
                    Protocols = ["test"],
                    ChainPolicy = new() {
                        TrustMode = X509ChainTrustMode.CustomRootTrust,
                        RevocationMode = X509RevocationMode.NoCheck,
                        CustomTrustStore = {
                            certificate
                        }
                    },
                    CancellationToken = timeoutSource.Token
                });

                source.SetResult();
            } catch(Exception e) {
                source.SetException(e);
            }
        });

        QuicConnection server = await QuicConnection.ListenAsync(new() {
            LocalPoint = IPEndPoint.Parse("0.0.0.0:50000"),
            Protocols = ["test"],
            CertificateChain = [certificate],
            CancellationToken = timeoutSource.Token
        });

        await source.Task;

        Assert.CatchAsync(async () => {
            await server.ReceiveStreamAsync();
        });
    }

    [Test, Explicit]
    public async Task ImmediateCloseTestAsync() {
        CancellationTokenSource timeoutSource = new(5000);

        QuicConnection client = null;

        TaskCompletionSource source = new();

        CertificateRequest request = new("cn=Test CA", RSA.Create(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        //CertificateRequest request = new("cn=Test CA", ECDsa.Create(), HashAlgorithmName.SHA256);

        X509Certificate2 certificate = request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));

        _ = Task.Run(async () => {
            try {
                client = await QuicConnection.ConnectAsync(new() {
                    RemotePoint = IPEndPoint.Parse("127.0.0.1:50000"),
                    Protocols = ["test"],
                    ChainPolicy = new() {
                        TrustMode = X509ChainTrustMode.CustomRootTrust,
                        RevocationMode = X509RevocationMode.NoCheck,
                        CustomTrustStore = {
                            certificate
                        }
                    },
                    CancellationToken = timeoutSource.Token
                });

                source.SetResult();

                await client.CloseAsync(0, ReadOnlyMemory<char>.Empty);
            } catch(Exception e) {
                source.SetException(e);
            }
        });

        QuicConnection server = await QuicConnection.ListenAsync(new() {
            LocalPoint = IPEndPoint.Parse("0.0.0.0:50000"),
            Protocols = ["test"],
            CertificateChain = [certificate],
            CancellationToken = timeoutSource.Token
        });

        await source.Task;

        await Task.Run(() => Assert.CatchAsync(async () => {
            await server.ReceiveStreamAsync();
        }));
    }
}
