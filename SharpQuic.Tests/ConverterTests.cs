using System;
using Xunit;

namespace SharpQuic.Tests;

public class ConverterTests {
    [Fact]
    public void HexToBytesTest() {
        Span<byte> span = stackalloc byte[4];

        Converter.HexToBytes("FF7F0F07", span);

        Assert.True(span is [255, 127, 15, 7]);
    }

    [Fact]
    public void BytesToHexTest() {
        string hex = Converter.BytesToHex([255, 127, 15, 7]);

        Assert.Equal("FF7F0F07", hex);
    }
}
