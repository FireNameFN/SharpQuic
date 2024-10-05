using System.Linq;
using System.Net;
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
            client = await QuicConnection.ConnectAsync(IPEndPoint.Parse("127.0.0.1:50000"), ["test"]);

            source.SetResult();
        });

        QuicConnection server = await QuicConnection.ListenAsync(IPEndPoint.Parse("0.0.0.0:50000"), ["test"]);

        await source.Task;

        Assert.That(client.protection.sourceKey.SequenceEqual(server.protection.destinationKey));
        Assert.That(client.protection.sourceIv.SequenceEqual(server.protection.destinationIv));
        Assert.That(client.protection.sourceHp.SequenceEqual(server.protection.destinationHp));
    }

    [Test, Explicit]
    public async Task ConnectToExternalServer() {
        await QuicConnection.ConnectAsync(IPEndPoint.Parse("127.0.0.1:853"), ["doq"]);
    }

    [Test, Explicit]
    public async Task ListenExternalClient() {
        await QuicConnection.ListenAsync(IPEndPoint.Parse("127.0.0.1:50000"), ["test"]);
    }
}
