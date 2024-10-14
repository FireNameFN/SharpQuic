using System;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using NUnit.Framework;

namespace SharpQuic.Tests;

[TestFixture]
public class CutStreamTests {
    [Test]
    public async Task FillTest() {
        CutStream array = new(1024);

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
    public async Task BigReadTest() {
        CutStream array = new(512);

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
}
