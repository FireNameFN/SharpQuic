using System;
using NUnit.Framework;

namespace SharpQuic.Tests;

[TestFixture]
public class ConverterTests {
    [Test]
    public void HexToBytesTest() {
        Span<byte> span = stackalloc byte[4];

        Converter.HexToBytes("FF7F0F07", span);

        Assert.That(span is [255, 127, 15, 7]);
    }

    [Test]
    public void BytesToHexTest() {
        string hex = Converter.BytesToHex([255, 127, 15, 7]);

        Assert.That(hex == "FF7F0F07");
    }
}
