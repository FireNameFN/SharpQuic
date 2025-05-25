using System;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using NUnit.Framework;

namespace SharpQuic.Tests;

[TestFixture]
public class QuicStreamTests {
    [Test, Explicit]
    public async Task QuicStreamTestAsync() {
        CancellationTokenSource timeoutSource = new(10000);

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
                    CancellationToken = timeoutSource.Token,
                    //DebugLogging = true
                });

                QuicStream stream = await client.OpenUnidirectionalStream();

                await stream.WriteAsync(data, true);

                source.SetResult();
            } catch(Exception e) {
                source.SetException(e);
            }
        });

        CertificateRequest request = new("cn=Test CA", RSA.Create(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        X509Certificate2 certificate = request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));

        QuicConnection server = await QuicConnection.ListenAsync(new() {
            LocalPoint = IPEndPoint.Parse("0.0.0.0:50000"),
            Protocols = ["test"],
            CertificateChain = [certificate],
            CancellationToken = timeoutSource.Token,
            //DebugLogging = true
        });

        /*server.OnStream += stream => {
            byte[] data

            stream.ReadAsync();
        };*/

        //server.str

        byte[] receiveData = new byte[data.Length];

        QuicStream stream = await server.ReceiveStream();

        //_ = Task.Run(() => stream.ReadAsync(receiveData));

        await stream.ReadAsync(receiveData);

        await source.Task;

        Assert.That(receiveData.AsSpan().SequenceEqual(data));
    }
    [Test, Explicit]
    public async Task QuicStreamSmallDataTestAsync() {
        CancellationTokenSource timeoutSource = new(200000);

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
                    CancellationToken = timeoutSource.Token,
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
        });

        CertificateRequest request = new("cn=Test CA", RSA.Create(), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        X509Certificate2 certificate = request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));

        QuicConnection server = await QuicConnection.ListenAsync(new() {
            LocalPoint = IPEndPoint.Parse("0.0.0.0:50000"),
            Protocols = ["test"],
            CertificateChain = [certificate],
            CancellationToken = timeoutSource.Token,
            //DebugLogging = true
        });

        /*server.OnStream += stream => {
            byte[] data

            stream.ReadAsync();
        };*/

        //server.str

        byte[] receiveData = new byte[data.Length];

        QuicStream stream = await server.ReceiveStream();

        //_ = Task.Run(() => stream.ReadAsync(receiveData));

        await stream.ReadAsync(receiveData);

        await source.Task;

        Assert.That(receiveData.AsSpan().SequenceEqual(data));
    }
}
