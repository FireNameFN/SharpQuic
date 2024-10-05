using System.IO;
using NUnit.Framework;

namespace SharpQuic.Tests;

[TestFixture]
public class SerializerTests {
    [Test]
    public void WriteVariableLengthOn5Test() {
        MemoryStream stream = new();

        Serializer.WriteVariableLength(stream, 5);

        byte[] array = stream.ToArray();

        Assert.That(array is [0b00_000101]);
    }

    [Test]
    public void WriteVariableLengthOn300Test() {
        MemoryStream stream = new();

        Serializer.WriteVariableLength(stream, 300);

        byte[] array = stream.ToArray();

        Assert.That(array is [0b01_000001, 0b00101100]);
    }

    [Test]
    public void ReadVeriableLengthOn5Test() {
        MemoryStream stream = new();

        stream.Write([0b00_000101]);

        stream.Position = 0;

        ulong value = Serializer.ReadVariableLength(stream).Value;

        Assert.That(value == 5);
    }

    [Test]
    public void ReadVeriableLengthOn300Test() {
        MemoryStream stream = new();

        stream.Write([0b01_000001, 0b00101100]);

        stream.Position = 0;

        ulong value = Serializer.ReadVariableLength(stream).Value;

        Assert.That(value == 300);
    }
}
