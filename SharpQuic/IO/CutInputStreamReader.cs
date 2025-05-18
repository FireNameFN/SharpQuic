using System;
using System.IO;

namespace SharpQuic.IO;

public sealed class CutInputStreamReader(CutInputStream stream) : Stream {
    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => false;

    public override long Length => (long)stream.Offset + stream.Length;

    public override long Position {
        get => (long)Offset;
        set => Offset = (ulong)value;
    }

    readonly CutInputStream stream = stream;

    public ulong Offset { get; private set; } = stream.Offset;

    public override void Flush() { }

    public override int Read(byte[] buffer, int offset, int count) {
        int length = stream.ReadWithoutAdvance(buffer.AsSpan().Slice(offset, count), Offset);

        Offset += (ulong)length;

        return length;
    }

    public override long Seek(long offset, SeekOrigin origin) {
        throw new NotSupportedException();
    }

    public override void SetLength(long value) {
        throw new NotSupportedException();
    }

    public override void Write(byte[] buffer, int offset, int count) {
        throw new NotSupportedException();
    }
}
