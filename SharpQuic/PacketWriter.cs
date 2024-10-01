using System;
using System.IO;

namespace SharpQuic;

public sealed class PacketWriter {
    internal readonly MemoryStream stream = new();

    public void WriteCrypto(ReadOnlySpan<byte> span) {
        Serializer.WriteVariableLength(stream, (ulong)FrameType.Crypto);

        Serializer.WriteVariableLength(stream, 0);

        Serializer.WriteVariableLength(stream, (ulong)span.Length);

        stream.Write(span);
    }
}
