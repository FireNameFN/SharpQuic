using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace SharpQuic;

public static class HKDFExtensions {
    static readonly byte[] TlsLabel = Encoding.ASCII.GetBytes("tls13 ");

    public static void ExpandLabel(HashAlgorithmName hashAlgorithmName, ReadOnlySpan<byte> secret, ReadOnlySpan<byte> label, ReadOnlySpan<byte> context, Span<byte> output) {
        Span<byte> lengthSpan = stackalloc byte[sizeof(ushort)];

        BinaryPrimitives.WriteUInt16BigEndian(lengthSpan, (ushort)output.Length);

        Span<byte> info = [..lengthSpan, (byte)(TlsLabel.Length + label.Length), ..TlsLabel, ..label, (byte)context.Length, ..context];

        HKDF.Expand(hashAlgorithmName, secret, output, info);
    }

    public static void ExpandLabel(ReadOnlySpan<byte> secret, string label, ReadOnlySpan<byte> context, Span<byte> output) {
        Span<byte> labelSpan = stackalloc byte[Encoding.ASCII.GetByteCount(label)];

        Encoding.ASCII.GetBytes(label, labelSpan);

        ExpandLabel(HashAlgorithmName.SHA256, secret, labelSpan, context, output);
    }

    public static void ExpandLabel(ReadOnlySpan<byte> secret, string label, Span<byte> output) {
        ExpandLabel(secret, label, [], output);
    }
}
