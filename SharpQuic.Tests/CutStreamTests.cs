using System;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using NUnit.Framework;
using SharpQuic.IO;

namespace SharpQuic.Tests;

[TestFixture]
public class CutStreamTests {
    [Test]
    public async Task FillAsyncTest() {
        CutInputStream array = new(1024);

        byte[] data = new byte[1024];

        RandomNumberGenerator.Fill(data);

        array.Write(data.AsSpan()[..100], 0);

        array.Write(data.AsSpan()[100..200], 100);

        array.Write(data.AsSpan()[50..150], 50);

        array.Write(data.AsSpan()[150..300], 150);

        array.Write(data.AsSpan()[300..400], 300);

        array.Write(data.AsSpan()[0..500], 0);

        array.Write(data.AsSpan()[700..800], 700);

        array.Write(data.AsSpan()[900..1024], 900);

        array.Write(data.AsSpan()[500..900], 500);

        byte[] readedData = new byte[1024];

        await array.ReadAsync(readedData);

        Assert.That(data.AsSpan().SequenceEqual(readedData));
    }

    [Test, Repeat(1000)]
    public async Task BigReadAsyncTest() {
        CutInputStream array = new(512);

        byte[] data = new byte[2048];

        RandomNumberGenerator.Fill(data);

        _ = Task.Run(() => {
            for(int i = 0; i < 2048; i += 256) {
                while(array.MaxData < (ulong)i + 256) ;
                
                array.Write(data.AsSpan()[i..(i+256)], (ulong)i);
            }
        });

        byte[] readData = new byte[2048];

        await array.ReadAsync(readData);

        Assert.That(data.AsSpan().SequenceEqual(readData));
    }

    [Test]
    public async Task SmallReadsAndWritesTest() {
        CutInputStream stream = new(1024);

        byte[] data = new byte[2048];

        RandomNumberGenerator.Fill(data);

        stream.Write(data.AsSpan()[..512], 0);

        byte[] readData = new byte[2048];

        await stream.ReadAsync(readData.AsMemory()[..256]);

        stream.Write(data.AsSpan()[512..1024], 512);

        await stream.ReadAsync(readData.AsMemory()[256..512]);

        await stream.ReadAsync(readData.AsMemory()[512..768]);

        await stream.ReadAsync(readData.AsMemory()[768..1024]);

        stream.Write(data.AsSpan()[1024..2048], 1024);

        await stream.ReadAsync(readData.AsMemory()[1024..1536]);

        await stream.ReadAsync(readData.AsMemory()[1536..2048]);

        Assert.That(data.AsSpan().SequenceEqual(readData));
    }
}
