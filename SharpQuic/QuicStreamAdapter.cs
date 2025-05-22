using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace SharpQuic;

public sealed class QuicStreamAdapter(QuicStream stream) : Stream {
    public QuicStream Stream { get; } = stream;

    public override bool CanRead => Stream.CanRead;

    public override bool CanSeek => false;

    public override bool CanWrite => Stream.CanWrite;

    public override long Length => throw new NotSupportedException();

    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public override void Flush() {
        throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count) {
        throw new NotSupportedException();
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

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) {
        await Stream.ReadAsync(buffer);

        return buffer.Length;
    }

    public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken = default) {
        await Stream.ReadAsync(buffer.AsMemory().Slice(offset, count));

        return count;
    }

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) {
        return new(Stream.WriteAsync(buffer));
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken = default) {
        return Stream.WriteAsync(buffer.AsMemory().Slice(offset, count));
    }

    public override Task FlushAsync(CancellationToken cancellationToken = default) {
        return Stream.FlushAsync().AsTask();
    }
}
