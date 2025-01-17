using System;
using System.Threading;
using System.Threading.Tasks;
using SharpQuic.IO;

namespace SharpQuic;

public sealed class QuicStream {
    public ulong Id { get; }

    readonly QuicConnection connection;

    readonly CutStream stream = new(1024);

    readonly PacketWriter packetWriter;

    readonly FrameWriter frameWriter = new();

    ulong offset;

    ulong peerMaxData = 1024;

    readonly SemaphoreSlim semaphore = new(0, 1);

    bool peerClosed;

    internal QuicStream(QuicConnection connection, ulong id) {
        this.connection = connection;
        Id = id;

        packetWriter = new(connection);

        stream.MaxDataIncreased += () => {
            if(peerClosed)
                return Task.CompletedTask;

            frameWriter.WriteMaxStreamData(Id, stream.MaxData);

            frameWriter.WritePaddingUntil(20);

            packetWriter.Write(PacketType.OneRtt, connection.applicationStage.GetNextPacketNumber(), frameWriter.ToPayload(), null);

            return connection.SendAsync(packetWriter).AsTask();
        };
    }

    public async Task WriteAsync(ReadOnlyMemory<byte> data, bool close = false) {
        int position = 0;

        while(position < data.Length) {
            int length = Math.Min(1200 - frameWriter.Length, (int)(peerMaxData - offset) - position);

            if(position + length > data.Length)
                length = data.Length - position;

            if(length < 1) {
                await semaphore.WaitAsync();

                length = Math.Min(1200 - frameWriter.Length, (int)(peerMaxData - offset) - position);

                if(position + length > data.Length)
                    length = data.Length - position;
            }

            frameWriter.WriteStream(data.Slice(position, length).Span, Id, offset + (ulong)position, position + length >= data.Length && close);

            frameWriter.WritePaddingUntil(1200);

            position += length;

            packetWriter.Write(PacketType.OneRtt, connection.applicationStage.GetNextPacketNumber(), frameWriter.ToPayload(), null);

            await connection.SendAsync(packetWriter);
        }

        offset += (ulong)data.Length;

        Console.WriteLine($"Stream Write {data.Length}");
    }

    public Task ReadAsync(Memory<byte> memory) {
        return stream.ReadAsync(memory);
    }

    internal void Put(ReadOnlySpan<byte> data, ulong offset, bool close) {
        stream.Write(data, offset);

        peerClosed = close;
    }

    internal void MaxStreamData(ulong maxStreamData) {
        if(maxStreamData <= peerMaxData)
            return;

        peerMaxData = maxStreamData;

        semaphore.Release();
    }
}
