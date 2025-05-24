using System;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using NUnit.Framework;

namespace SharpQuic.Tests;

[TestFixture]
public class QuicConnectionTests {
    [Test, Explicit]
    public async Task QuicConnectionTestAsync() {
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

        Assert.That(client.applicationStage.KeySet.SourceKey.AsSpan().SequenceEqual(server.applicationStage.KeySet.DestinationKey));
        Assert.That(client.applicationStage.KeySet.SourceIv.AsSpan().SequenceEqual(server.applicationStage.KeySet.DestinationIv));
        Assert.That(client.applicationStage.KeySet.SourceHp.AsSpan().SequenceEqual(server.applicationStage.KeySet.DestinationHp));
    }

    [Test, Explicit]
    public async Task QuicConnectionClientAuthenticationTestAsync() {
        CancellationTokenSource timeoutSource = new(5000);

        QuicConnection client = null;

        TaskCompletionSource source = new();

        CertificateRequest request = new("cn=Test CA", RSA.Create(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        //CertificateRequest request = new("cn=Test CA", ECDsa.Create(), HashAlgorithmName.SHA256);

        X509Certificate2 clientCertificate = request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));

        X509Certificate2 serverCertificate = request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));

        _ = Task.Run(async () => {
            try {
                client = await QuicConnection.ConnectAsync(new() {
                    RemotePoint = IPEndPoint.Parse("127.0.0.1:50000"),
                    Protocols = ["test"],
                    CertificateChain = [clientCertificate],
                    ChainPolicy = new() {
                        TrustMode = X509ChainTrustMode.CustomRootTrust,
                        RevocationMode = X509RevocationMode.NoCheck,
                        CustomTrustStore = {
                            serverCertificate
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
            CertificateChain = [serverCertificate],
            ChainPolicy = new() {
                TrustMode = X509ChainTrustMode.CustomRootTrust,
                RevocationMode = X509RevocationMode.NoCheck,
                CustomTrustStore = {
                    clientCertificate
                }
            },
            ClientAuthentication = true,
            CancellationToken = timeoutSource.Token
        });

        await source.Task;

        Assert.That(client.applicationStage.KeySet.SourceKey.AsSpan().SequenceEqual(server.applicationStage.KeySet.DestinationKey));
        Assert.That(client.applicationStage.KeySet.SourceIv.AsSpan().SequenceEqual(server.applicationStage.KeySet.DestinationIv));
        Assert.That(client.applicationStage.KeySet.SourceHp.AsSpan().SequenceEqual(server.applicationStage.KeySet.DestinationHp));
    }

    [Test, Explicit]
    public async Task QuicDoubleConnectionTestAsync() {
        CancellationTokenSource timeoutSource = new(1500);

        CertificateRequest request = new("cn=Test CA", RSA.Create(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        X509Certificate2 certificate = request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));

        /*SemaphoreSlim semaphore = new(0);

        QuicListener listener = new(new() {
            LocalPoint = IPEndPoint.Parse("0.0.0.0:50000"),
            Protocols = ["test"],
            CertificateChain = [certificate],
            CancellationToken = timeoutSource.Token
        });

        listener.OnConnection += _ => {
            semaphore.Release();
        };

        await listener.StartAsync();*/

        TaskCompletionSource source1 = new();

        _ = Task.Run(async () => {
            try {
                QuicConnection client = await QuicConnection.ConnectAsync(new() {
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

                source1.SetResult();
            } catch(Exception e) {
                source1.SetException(e);
            }
        });

        TaskCompletionSource source2 = new();

        _ = Task.Run(async () => {
            try {
                QuicConnection client = await QuicConnection.ConnectAsync(new() {
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

                source2.SetResult();
            } catch(Exception e) {
                source2.SetException(e);
            }
        });

        TaskCompletionSource source3 = new();

        _ = Task.Run(async () => {
            try {
                QuicConnection client = await QuicConnection.ListenAsync(new() {
                    LocalPoint = IPEndPoint.Parse("0.0.0.0:50000"),
                    Protocols = ["test"],
                    CertificateChain = [certificate],
                    CancellationToken = timeoutSource.Token
                });

                source3.SetResult();
            } catch(Exception e) {
                source3.SetException(e);
            }
        });

        TaskCompletionSource source4 = new();

        _ = Task.Run(async () => {
            try {
                QuicConnection client = await QuicConnection.ListenAsync(new() {
                    LocalPoint = IPEndPoint.Parse("0.0.0.0:50000"),
                    Protocols = ["test"],
                    CertificateChain = [certificate],
                    CancellationToken = timeoutSource.Token
                });

                source4.SetResult();
            } catch(Exception e) {
                source4.SetException(e);
            }
        });

        await source1.Task;

        await source2.Task;

        await source3.Task;

        await source4.Task;

        //await semaphore.WaitAsync(timeoutSource.Token);

        //await semaphore.WaitAsync(timeoutSource.Token);
    }

    [Test, Explicit]
    public async Task QuicDoubleConnectionFromOnePointTestAsync() {
        CancellationTokenSource timeoutSource = new(1500);

        CertificateRequest request = new("cn=Test CA", RSA.Create(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        X509Certificate2 certificate = request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));

        TaskCompletionSource source3 = new();

        _ = Task.Run(async () => {
            try {
                QuicConnection client = await QuicConnection.ListenAsync(new() {
                    LocalPoint = IPEndPoint.Parse("0.0.0.0:50000"),
                    Protocols = ["test"],
                    CertificateChain = [certificate],
                    CancellationToken = timeoutSource.Token
                });

                source3.SetResult();
            } catch(Exception e) {
                source3.SetException(e);
            }
        });

        TaskCompletionSource source4 = new();

        _ = Task.Run(async () => {
            try {
                QuicConnection client = await QuicConnection.ListenAsync(new() {
                    LocalPoint = IPEndPoint.Parse("0.0.0.0:50000"),
                    Protocols = ["test"],
                    CertificateChain = [certificate],
                    CancellationToken = timeoutSource.Token
                });

                source4.SetResult();
            } catch(Exception e) {
                source4.SetException(e);
            }
        });

        QuicConnection client = await QuicConnection.ConnectAsync(new() {
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

        QuicConnection client2 = await QuicConnection.ConnectAsync(new() {
            LocalPoint = client.LocalPoint,
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

        await source3.Task;

        await source4.Task;
    }

    [Test, Explicit]
    public async Task ConnectToExternalServerTestAsync() {
        await QuicConnection.ConnectAsync(new() {
            RemotePoint = IPEndPoint.Parse("127.0.0.1:853"),
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
            LocalPoint = IPEndPoint.Parse("127.0.0.1:50000"),
            Protocols = ["test"],
            CertificateChain = [certificate]
        });
    }
}
