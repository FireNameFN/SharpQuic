using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace SharpQuic.Tls;

public static class HKDFExtensions {
    static readonly byte[] TlsLabel = Encoding.ASCII.GetBytes("tls13 ");

    public static void ExpandLabel(HashAlgorithmName name, ReadOnlySpan<byte> secret, string label, ReadOnlySpan<byte> context, Span<byte> output) {
        Span<byte> lengthSpan = stackalloc byte[sizeof(ushort)];

        BinaryPrimitives.WriteUInt16BigEndian(lengthSpan, (ushort)output.Length);

        Span<byte> labelSpan = stackalloc byte[Encoding.ASCII.GetMaxByteCount(label.Length)];

        int length = Encoding.ASCII.GetBytes(label, labelSpan);

        Span<byte> info = [..lengthSpan, (byte)(TlsLabel.Length + label.Length), ..TlsLabel, ..labelSpan[..length], (byte)context.Length, ..context];

        HKDF.Expand(name, secret, output, info);
    }

    public static void ExpandLabel(HashAlgorithmName name, ReadOnlySpan<byte> secret, string label, Span<byte> output) {
        ExpandLabel(name, secret, label, [], output);
    }
}
