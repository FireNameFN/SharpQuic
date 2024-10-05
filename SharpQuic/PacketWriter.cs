using System;
using System.IO;
using SharpQuic.Tls;

namespace SharpQuic;

public sealed class PacketWriter : IFragmentWriter {
    internal readonly MemoryStream stream = new();

    public void WriteCrypto(ReadOnlySpan<byte> span) {
        Serializer.WriteVariableLength(stream, (ulong)FrameType.Crypto);

        Serializer.WriteVariableLength(stream, 0);

        Serializer.WriteVariableLength(stream, (ulong)span.Length);

        stream.Write(span);
    }

    public void WritePaddingUntil1200() {
        Span<byte> padding = stackalloc byte[1200 - (int)stream.Position];
        
        stream.Write(padding);
    }

    void IFragmentWriter.WriteFragment(ReadOnlySpan<byte> fragment) {
        WriteCrypto(fragment);
    }
}
