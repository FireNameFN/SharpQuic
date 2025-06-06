using System;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace SharpQuic.Tests;

public class QuicConnectionCloseTests {
    [Fact(Explicit = true)]
    public async Task IdleTimeoutTestAsync() {
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
                    }
                });

                source.SetResult();
            } catch(Exception e) {
                source.SetException(e);
            }
        }, TestContext.Current.CancellationToken);

        QuicConnection server = await QuicConnection.ListenAsync(new() {
            LocalPoint = IPEndPoint.Parse("0.0.0.0:50000"),
            Protocols = ["test"],
            CertificateChain = [certificate]
        });

        await source.Task;

        await Assert.ThrowsAsync<OperationCanceledException>(async () => {
            await server.ReceiveStreamAsync();
        });
    }

    [Fact(Explicit = true)]
    public async Task ImmediateCloseTestAsync() {
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
                    }
                });

                source.SetResult();

                await client.CloseAsync(0, ReadOnlyMemory<char>.Empty);
            } catch(Exception e) {
                source.SetException(e);
            }
        }, TestContext.Current.CancellationToken);

        QuicConnection server = await QuicConnection.ListenAsync(new() {
            LocalPoint = IPEndPoint.Parse("0.0.0.0:50000"),
            Protocols = ["test"],
            CertificateChain = [certificate]
        });

        await source.Task;

        await Assert.ThrowsAsync<OperationCanceledException>(async () => {
            await server.ReceiveStreamAsync();
        });
    }
}
