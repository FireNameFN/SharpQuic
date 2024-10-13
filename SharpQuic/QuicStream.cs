using System;
using System.Buffers.Binary;
using System.Threading.Tasks;

namespace SharpQuic;

public sealed class QuicStream {
    public ulong Id { get; }

    readonly QuicConnection connection;

    ulong offset;

    internal QuicStream(QuicConnection connection, ulong id) {
        this.connection = connection;
        Id = id;
    }

    public Task WriteAsync(ReadOnlySpan<byte> data, bool close = false) {
        connection.applicationStage.FrameWriter.WriteStream(data, Id, offset, close);

        connection.applicationStage.FrameWriter.WritePaddingUntil(1200);

        offset += (ulong)data.Length;

        Console.WriteLine($"Stream Write {data.Length}");

        return connection.FlushAsync().AsTask();
    }
}
