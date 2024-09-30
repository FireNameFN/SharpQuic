using System;

namespace SharpQuic;

public static class Converter {
    public static void HexToBytes(ReadOnlySpan<char> hex, Span<byte> output) {
        for(int i = 0; i < hex.Length / 2; i++)
            output[i] = byte.Parse(hex.Slice(i*2, 2), System.Globalization.NumberStyles.HexNumber);
    }

    public static string BytesToHex(ReadOnlySpan<byte> bytes) {
        Span<char> hex = stackalloc char[bytes.Length * 2];

        for(int i = 0; i < bytes.Length; i++)
            bytes[i].TryFormat(hex[(i * 2)..], out _, "X2");

        return hex.ToString();
    }
}
