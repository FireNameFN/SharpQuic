using System;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace SharpQuic.Tests;

public class QuicConnectionTests {
    [Fact(Explicit = true)]
    public async Task QuicConnectionTestAsync() {
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

        Assert.True(client.applicationStage.KeySet.SourceKey.AsSpan().SequenceEqual(server.applicationStage.KeySet.DestinationKey));
        Assert.True(client.applicationStage.KeySet.SourceIv.AsSpan().SequenceEqual(server.applicationStage.KeySet.DestinationIv));
        Assert.True(client.applicationStage.KeySet.SourceHp.AsSpan().SequenceEqual(server.applicationStage.KeySet.DestinationHp));
    }

    [Fact(Explicit = true)]
    public async Task QuicConnectionClientAuthenticationTestAsync() {
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
            CertificateChain = [serverCertificate],
            ChainPolicy = new() {
                TrustMode = X509ChainTrustMode.CustomRootTrust,
                RevocationMode = X509RevocationMode.NoCheck,
                CustomTrustStore = {
                    clientCertificate
                }
            },
            ClientAuthentication = true
        });

        await source.Task;

        Assert.True(client.applicationStage.KeySet.SourceKey.AsSpan().SequenceEqual(server.applicationStage.KeySet.DestinationKey));
        Assert.True(client.applicationStage.KeySet.SourceIv.AsSpan().SequenceEqual(server.applicationStage.KeySet.DestinationIv));
        Assert.True(client.applicationStage.KeySet.SourceHp.AsSpan().SequenceEqual(server.applicationStage.KeySet.DestinationHp));
    }

    [Fact(Explicit = true)]
    public async Task QuicDoubleConnectionTestAsync() {
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
                    }
                });

                source1.SetResult();
            } catch(Exception e) {
                source1.SetException(e);
            }
        }, TestContext.Current.CancellationToken);

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
                    }
                });

                source2.SetResult();
            } catch(Exception e) {
                source2.SetException(e);
            }
        }, TestContext.Current.CancellationToken);

        TaskCompletionSource source3 = new();

        _ = Task.Run(async () => {
            try {
                QuicConnection client = await QuicConnection.ListenAsync(new() {
                    LocalPoint = IPEndPoint.Parse("0.0.0.0:50000"),
                    Protocols = ["test"],
                    CertificateChain = [certificate]
                });

                source3.SetResult();
            } catch(Exception e) {
                source3.SetException(e);
            }
        }, TestContext.Current.CancellationToken);

        TaskCompletionSource source4 = new();

        _ = Task.Run(async () => {
            try {
                QuicConnection client = await QuicConnection.ListenAsync(new() {
                    LocalPoint = IPEndPoint.Parse("0.0.0.0:50000"),
                    Protocols = ["test"],
                    CertificateChain = [certificate]
                });

                source4.SetResult();
            } catch(Exception e) {
                source4.SetException(e);
            }
        }, TestContext.Current.CancellationToken);

        await source1.Task;

        await source2.Task;

        await source3.Task;

        await source4.Task;

        //await semaphore.WaitAsync(timeoutSource.Token);

        //await semaphore.WaitAsync(timeoutSource.Token);
    }

    [Fact(Explicit = true)]
    public async Task QuicDoubleConnectionFromOnePointTestAsync() {
        CertificateRequest request = new("cn=Test CA", RSA.Create(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        X509Certificate2 certificate = request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));

        TaskCompletionSource source3 = new();

        _ = Task.Run(async () => {
            try {
                QuicConnection client = await QuicConnection.ListenAsync(new() {
                    LocalPoint = IPEndPoint.Parse("0.0.0.0:50000"),
                    Protocols = ["test"],
                    CertificateChain = [certificate]
                });

                source3.SetResult();
            } catch(Exception e) {
                source3.SetException(e);
            }
        }, TestContext.Current.CancellationToken);

        TaskCompletionSource source4 = new();

        _ = Task.Run(async () => {
            try {
                QuicConnection client = await QuicConnection.ListenAsync(new() {
                    LocalPoint = IPEndPoint.Parse("0.0.0.0:50000"),
                    Protocols = ["test"],
                    CertificateChain = [certificate]
                });

                source4.SetResult();
            } catch(Exception e) {
                source4.SetException(e);
            }
        }, TestContext.Current.CancellationToken);

        QuicConnection client = await QuicConnection.ConnectAsync(new() {
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
            }
        });

        await source3.Task;

        await source4.Task;
    }

    [Fact(Explicit = true)]
    public async Task ConnectToExternalServerTestAsync() {
        await QuicConnection.ConnectAsync(new() {
            RemotePoint = IPEndPoint.Parse("127.0.0.1:853"),
            Protocols = ["doq"]
        });
    }

    [Fact(Explicit = true)]
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
