using System.IO;
using Xunit;

namespace SharpQuic.Tests;

public class SerializerTests {
    [Fact]
    public void WriteVariableLengthOn5Test() {
        MemoryStream stream = new();

        Serializer.WriteVariableLength(stream, 5);

        byte[] array = stream.ToArray();

        Assert.True(array is [0b00_000101]);
    }

    [Fact]
    public void WriteVariableLengthOn300Test() {
        MemoryStream stream = new();

        Serializer.WriteVariableLength(stream, 300);

        byte[] array = stream.ToArray();

        Assert.True(array is [0b01_000001, 0b00101100]);
    }

    [Fact]
    public void ReadVeriableLengthOn5Test() {
        MemoryStream stream = new();

        stream.Write([0b00_000101]);

        stream.Position = 0;

        ulong value = Serializer.ReadVariableLength(stream).Value;

        Assert.Equal(5u, value);
    }

    [Fact]
    public void ReadVeriableLengthOn300Test() {
        MemoryStream stream = new();

        stream.Write([0b01_000001, 0b00101100]);

        stream.Position = 0;

        ulong value = Serializer.ReadVariableLength(stream).Value;

        Assert.Equal(300u, value);
    }
}
