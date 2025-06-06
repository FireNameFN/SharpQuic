using System;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace SharpQuic.Tests;

public class QuicStreamTests {
    [Fact(Explicit = true)]
    public async Task QuicStreamTestAsync() {
        byte[] data = new byte[(1 << 20) * 100];

        RandomNumberGenerator.Fill(data);

        QuicConnection client = null;

        TaskCompletionSource source = new();

        _ = Task.Run(async () => {
            try {
                client = await QuicConnection.ConnectAsync(new() {
                    RemotePoint = IPEndPoint.Parse("127.0.0.1:50000"),
                    Protocols = ["test"],
                    ChainPolicy = new() {
                        VerificationFlags = X509VerificationFlags.AllFlags
                    }
                    //DebugLogging = true
                });

                QuicStream stream = await client.OpenUnidirectionalStream();

                long time = Stopwatch.GetTimestamp();

                for(int i = 0; i < 100; i++) {
                    Console.WriteLine(i);
                    Console.WriteLine((Stopwatch.GetTimestamp() - time) * 1000 / Stopwatch.Frequency);
                    Console.WriteLine(client.applicationStage.congestionWindow);
                    Console.WriteLine();
                    await stream.WriteAsync(data.AsMemory().Slice((1 << 20) * i, 1 << 20));
                }

                await stream.FlushAsync(true);

                source.SetResult();
            } catch(Exception e) {
                Console.WriteLine(e);

                source.SetException(e);
            }
        }, TestContext.Current.CancellationToken);

        CertificateRequest request = new("cn=Test CA", RSA.Create(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        X509Certificate2 certificate = request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));

        QuicConnection server = await QuicConnection.ListenAsync(new() {
            LocalPoint = IPEndPoint.Parse("0.0.0.0:50000"),
            Protocols = ["test"],
            CertificateChain = [certificate]
            //DebugLogging = true,
            //DebugInputPacketLoss = 0.01,
            //DebugOutputPacketLoss = 0.01
        });

        /*server.OnStream += stream => {
            byte[] data

            stream.ReadAsync();
        };*/

        //server.str

        byte[] receiveData = new byte[data.Length];

        QuicStream stream = await server.ReceiveStreamAsync();

        //_ = Task.Run(() => stream.ReadAsync(receiveData));

        await stream.ReadAsync(receiveData);

        await source.Task;

        Assert.True(receiveData.AsSpan().SequenceEqual(data));
    }

    [Fact(Explicit = true)]
    public async Task QuicStreamDelayTestAsync() {
        byte[] data = new byte[(1 << 20) * 10];

        RandomNumberGenerator.Fill(data);

        QuicConnection client = null;

        TaskCompletionSource source = new();

        _ = Task.Run(async () => {
            try {
                client = await QuicConnection.ConnectAsync(new() {
                    RemotePoint = IPEndPoint.Parse("127.0.0.1:50000"),
                    Protocols = ["test"],
                    ChainPolicy = new() {
                        VerificationFlags = X509VerificationFlags.AllFlags
                    },
                    //DebugLogging = true
                    DebugOutputDelay = 50
                });

                QuicStream stream = await client.OpenUnidirectionalStream();

                long time = Stopwatch.GetTimestamp();

                for(int i = 0; i < 256; i++) {
                    Console.WriteLine(i);
                    Console.WriteLine((Stopwatch.GetTimestamp() - time) * 1000 / Stopwatch.Frequency);
                    Console.WriteLine(client.applicationStage.congestionWindow);
                    Console.WriteLine();
                    await stream.WriteAsync(data.AsMemory().Slice(1024 * 40 * i, 1024 * 40));
                }

                await stream.FlushAsync(true);

                source.SetResult();
            } catch(Exception e) {
                Console.WriteLine(e);

                source.SetException(e);
            }
        }, TestContext.Current.CancellationToken);

        CertificateRequest request = new("cn=Test CA", RSA.Create(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        X509Certificate2 certificate = request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));

        QuicConnection server = await QuicConnection.ListenAsync(new() {
            LocalPoint = IPEndPoint.Parse("0.0.0.0:50000"),
            Protocols = ["test"],
            CertificateChain = [certificate],
            //DebugLogging = true,
            //DebugInputPacketLoss = 0.01,
            //DebugOutputPacketLoss = 0.01,
            DebugOutputDelay = 50
        });

        /*server.OnStream += stream => {
            byte[] data

            stream.ReadAsync();
        };*/

        //server.str

        byte[] receiveData = new byte[data.Length];

        QuicStream stream = await server.ReceiveStreamAsync();

        //_ = Task.Run(() => stream.ReadAsync(receiveData));

        await stream.ReadAsync(receiveData);

        await source.Task;

        Assert.True(receiveData.AsSpan().SequenceEqual(data));
    }

    [Fact(Explicit = true)]
    public async Task QuicStreamSmallDataTestAsync() {
        byte[] data = new byte[8192];

        RandomNumberGenerator.Fill(data);

        QuicConnection client = null;

        TaskCompletionSource source = new();

        _ = Task.Run(async () => {
            try {
                client = await QuicConnection.ConnectAsync(new() {
                    RemotePoint = IPEndPoint.Parse("127.0.0.1:50000"),
                    Protocols = ["test"],
                    ChainPolicy = new() {
                        VerificationFlags = X509VerificationFlags.AllFlags
                    },
                    DebugLogging = true
                });

                QuicStream stream = await client.OpenUnidirectionalStream();

                for(int i = 0; i < data.Length; i++)
                    await stream.WriteAsync(data.AsMemory().Slice(i, 1));

                await stream.FlushAsync(true);

                source.SetResult();
            } catch(Exception e) {
                source.SetException(e);
            }
        }, TestContext.Current.CancellationToken);

        CertificateRequest request = new("cn=Test CA", RSA.Create(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        X509Certificate2 certificate = request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));

        QuicConnection server = await QuicConnection.ListenAsync(new() {
            LocalPoint = IPEndPoint.Parse("0.0.0.0:50000"),
            Protocols = ["test"],
            CertificateChain = [certificate]
            //DebugLogging = true
        });

        /*server.OnStream += stream => {
            byte[] data

            stream.ReadAsync();
        };*/

        //server.str

        byte[] receiveData = new byte[data.Length];

        QuicStream stream = await server.ReceiveStreamAsync();

        //_ = Task.Run(() => stream.ReadAsync(receiveData));

        await stream.ReadAsync(receiveData);

        await source.Task;

        Assert.True(receiveData.AsSpan().SequenceEqual(data));
    }

    [Fact(Explicit = true)]
    public async Task QuicStreamChunksTestAsync() {
        byte[] data = new byte[(1 << 20) * 10];

        RandomNumberGenerator.Fill(data);

        QuicConnection client = null;

        TaskCompletionSource source = new();

        _ = Task.Run(async () => {
            try {
                client = await QuicConnection.ConnectAsync(new() {
                    RemotePoint = IPEndPoint.Parse("127.0.0.1:50000"),
                    Protocols = ["test"],
                    ChainPolicy = new() {
                        VerificationFlags = X509VerificationFlags.AllFlags
                    },
                    DebugLogging = true
                });

                QuicStream stream = await client.OpenUnidirectionalStream();

                QuicStreamAdapter adapter = new(stream);

                for(int i = 0; i < 1024; i++)
                    await adapter.WriteAsync(data.AsMemory().Slice(i, 1));

                await adapter.WriteAsync(data.AsMemory()[1024..1024000]);

                await adapter.WriteAsync(data.AsMemory()[1024000..]);

                await adapter.FlushAsync();

                await stream.FlushAsync(true);

                source.SetResult();
            } catch(Exception e) {
                source.SetException(e);
            }
        }, TestContext.Current.CancellationToken);

        CertificateRequest request = new("cn=Test CA", RSA.Create(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        X509Certificate2 certificate = request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));

        QuicConnection server = await QuicConnection.ListenAsync(new() {
            LocalPoint = IPEndPoint.Parse("0.0.0.0:50000"),
            Protocols = ["test"],
            CertificateChain = [certificate]
            //DebugLogging = true
        });

        /*server.OnStream += stream => {
            byte[] data

            stream.ReadAsync();
        };*/

        //server.str

        byte[] receiveData = new byte[data.Length];

        QuicStream stream = await server.ReceiveStreamAsync();

        QuicStreamAdapter adapter = new(stream);

        //_ = Task.Run(() => stream.ReadAsync(receiveData));

        await adapter.ReadExactlyAsync(receiveData.AsMemory()[..1024], TestContext.Current.CancellationToken);
        await adapter.ReadExactlyAsync(receiveData.AsMemory()[1024..512000], TestContext.Current.CancellationToken);
        await adapter.ReadExactlyAsync(receiveData.AsMemory()[512000..5120000], TestContext.Current.CancellationToken);
        await adapter.ReadExactlyAsync(receiveData.AsMemory()[5120000..], TestContext.Current.CancellationToken);

        await source.Task;

        Assert.True(receiveData.AsSpan().SequenceEqual(data));
    }

    [Fact(Explicit = true)]
    public async Task QuicStreamBidirectionalTestAsync() {
        byte[] data = new byte[(1 << 20) * 10];

        RandomNumberGenerator.Fill(data);

        QuicConnection client = null;

        TaskCompletionSource source = new();

        _ = Task.Run(async () => {
            try {
                client = await QuicConnection.ConnectAsync(new() {
                    RemotePoint = IPEndPoint.Parse("127.0.0.1:50000"),
                    Protocols = ["test"],
                    ChainPolicy = new() {
                        VerificationFlags = X509VerificationFlags.AllFlags
                    },
                    DebugLogging = true
                });

                QuicStream stream = await client.OpenBidirectionalStream();

                QuicStreamAdapter adapter = new(stream);

                byte[] b = new byte[1];

                await adapter.WriteAsync(b);

                await adapter.FlushAsync();

                byte[] receiveData = new byte[data.Length];

                //_ = Task.Run(() => stream.ReadAsync(receiveData));

                await adapter.ReadExactlyAsync(receiveData.AsMemory()[..1024]);
                await adapter.ReadExactlyAsync(receiveData.AsMemory()[1024..512000]);
                await adapter.ReadExactlyAsync(receiveData.AsMemory()[512000..5120000]);
                await adapter.ReadExactlyAsync(receiveData.AsMemory()[5120000..]);

                source.SetResult();
            } catch(Exception e) {
                source.SetException(e);
            }
        }, TestContext.Current.CancellationToken);

        CertificateRequest request = new("cn=Test CA", RSA.Create(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        X509Certificate2 certificate = request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));

        QuicConnection server = await QuicConnection.ListenAsync(new() {
            LocalPoint = IPEndPoint.Parse("0.0.0.0:50000"),
            Protocols = ["test"],
            CertificateChain = [certificate]
            //DebugLogging = true
        });

        QuicStream stream = await server.ReceiveStreamAsync();

        QuicStreamAdapter adapter = new(stream);

        byte[] b = new byte[1];

        await adapter.ReadExactlyAsync(b, TestContext.Current.CancellationToken);

        for(int i = 0; i < 1024; i++)
            await adapter.WriteAsync(data.AsMemory().Slice(i, 1), TestContext.Current.CancellationToken);

        await adapter.WriteAsync(data.AsMemory()[1024..1024000], TestContext.Current.CancellationToken);

        await adapter.WriteAsync(data.AsMemory()[1024000..], TestContext.Current.CancellationToken);

        await adapter.FlushAsync(TestContext.Current.CancellationToken);

        await stream.FlushAsync(true);

        await source.Task;
    }
}
