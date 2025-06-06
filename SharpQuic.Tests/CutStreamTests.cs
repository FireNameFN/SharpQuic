using System;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using SharpQuic.IO;
using Xunit;

namespace SharpQuic.Tests;

public class CutStreamTests {
    [Fact]
    public async Task FillTestAsync() {
        CutInputStream array = new(1024);

        byte[] data = new byte[1024];

        RandomNumberGenerator.Fill(data);

        await array.WriteAsync(data.AsMemory()[..100], 0);

        await array.WriteAsync(data.AsMemory()[100..200], 100);

        await array.WriteAsync(data.AsMemory()[50..150], 50);

        await array.WriteAsync(data.AsMemory()[150..300], 150);

        await array.WriteAsync(data.AsMemory()[300..400], 300);

        await array.WriteAsync(data.AsMemory()[0..500], 0);

        await array.WriteAsync(data.AsMemory()[700..800], 700);

        await array.WriteAsync(data.AsMemory()[900..1024], 900);

        await array.WriteAsync(data.AsMemory()[500..900], 500);

        byte[] readedData = new byte[1024];

        await array.ReadAsync(readedData, TestContext.Current.CancellationToken);

        Assert.True(data.AsSpan().SequenceEqual(readedData));
    }

    [Fact]
    public async Task BigReadTestAsync() {
        CutInputStream array = new(512);

        byte[] data = new byte[2048];

        RandomNumberGenerator.Fill(data);

        _ = Task.Run(async () => {
            for(int i = 0; i < 2048; i += 256) {
                while(array.MaxData < (ulong)i + 256) ;
                
                await array.WriteAsync(data.AsMemory()[i..(i+256)], (ulong)i);
            }
        }, TestContext.Current.CancellationToken);

        byte[] readData = new byte[2048];

        await array.ReadAsync(readData, TestContext.Current.CancellationToken);

        Assert.True(data.AsSpan().SequenceEqual(readData));
    }

    [Fact]
    public async Task SmallReadsAndWritesTest() {
        CutInputStream stream = new(1024);

        byte[] data = new byte[2048];

        RandomNumberGenerator.Fill(data);

        await stream.WriteAsync(data.AsMemory()[..512], 0);

        byte[] readData = new byte[2048];

        await stream.ReadAsync(readData.AsMemory()[..256], TestContext.Current.CancellationToken);

        await stream.WriteAsync(data.AsMemory()[512..1024], 512);

        await stream.ReadAsync(readData.AsMemory()[256..512], TestContext.Current.CancellationToken);

        await stream.ReadAsync(readData.AsMemory()[512..768], TestContext.Current.CancellationToken);

        await stream.ReadAsync(readData.AsMemory()[768..1024], TestContext.Current.CancellationToken);

        await stream.WriteAsync(data.AsMemory()[1024..2048], 1024);

        await stream.ReadAsync(readData.AsMemory()[1024..1536], TestContext.Current.CancellationToken);

        await stream.ReadAsync(readData.AsMemory()[1536..2048], TestContext.Current.CancellationToken);

        Assert.True(data.AsSpan().SequenceEqual(readData));
    }
}
