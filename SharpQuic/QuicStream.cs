using System;
using System.Threading.Tasks;
using SharpQuic.IO;

namespace SharpQuic;

public sealed class QuicStream {
    public ulong Id { get; }

    readonly QuicConnection connection;

    readonly CutStream stream = new(1024);

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

    public Task ReadAsync(Memory<byte> memory) {
        return stream.ReadAsync(memory);
    }

    internal void Put(ReadOnlySpan<byte> data, ulong offset) {
        stream.Write(data, offset);
    }
}
