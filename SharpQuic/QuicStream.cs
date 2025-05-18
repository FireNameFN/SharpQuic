using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using SharpQuic.IO;

namespace SharpQuic;

public sealed class QuicStream {
    public ulong Id { get; }

    readonly QuicConnection connection;

    readonly CutInputStream inputStream = new(1024);

    readonly CutOutputStream outputStream = new(102400);

    readonly Dictionary<uint, PacketInfo> packets = [];

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

        inputStream.MaxDataIncreased += () => {
            if(peerClosed)
                return Task.CompletedTask;

            return SendMaxData().AsTask();
        };
    }

    public async Task WriteAsync(ReadOnlyMemory<byte> data, bool close = false) {
        outputStream.Write(data.Span);

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

            /*frameWriter.WriteStream(data.Slice(position, length).Span, Id, offset + (ulong)position, position + length >= data.Length && close);

            frameWriter.WritePaddingUntil(1200);

            position += length;

            uint number = connection.applicationStage.GetNextPacketNumber(true);

            packetWriter.Write(PacketType.OneRtt, number, frameWriter.ToPayload(), null);

            packets.Add(number, new(true, offset + (ulong)position, length, position + length >= data.Length && close));

            await connection.SendAsync(packetWriter);*/

            await SendStreamAsync(data.Slice(position, length).Span, offset + (ulong)position, position + length >= data.Length && close);

            position += length;
        }

        offset += (ulong)data.Length;

        Console.WriteLine($"Stream Write {data.Length}");
    }

    public Task ReadAsync(Memory<byte> memory) {
        return inputStream.ReadAsync(memory, connection.cancellationToken);
    }

    internal void Put(ReadOnlySpan<byte> data, ulong offset, bool close) {
        inputStream.Write(data, offset);

        peerClosed = close;
    }

    internal void MaxStreamData(ulong maxStreamData) {
        if(maxStreamData <= peerMaxData)
            return;

        peerMaxData = maxStreamData;

        semaphore.Release();
    }

    internal void PacketAck(uint number) {
        packets.Remove(number);
    }

    internal ValueTask<int> PacketLostAsync(uint number) {
        packets.Remove(number, out PacketInfo info);

        if(!info.Data)
            return SendMaxData();

        Span<byte> data = stackalloc byte[info.Length];

        outputStream.Read(data, info.Offset);

        return SendStreamAsync(data, info.Offset, info.Fin);
    }

    ValueTask<int> SendStreamAsync(ReadOnlySpan<byte> data, ulong offset, bool fin) {
        frameWriter.WriteStream(data, Id, offset, fin);

        frameWriter.WritePaddingUntil(1200);

        uint number = connection.applicationStage.GetNextPacketNumber(true, Id);

        packetWriter.Write(PacketType.OneRtt, number, frameWriter.ToPayload(), null);

        packets.Add(number, new(true, offset, data.Length, fin));

        return connection.SendAsync(packetWriter);
    }

    ValueTask<int> SendMaxData() {
        frameWriter.WriteMaxStreamData(Id, inputStream.MaxData);

        frameWriter.WritePaddingUntil(20);

        uint number = connection.applicationStage.GetNextPacketNumber(true, Id);

        packetWriter.Write(PacketType.OneRtt, number, frameWriter.ToPayload(), null);

        packets.Add(number, new(false, 0, 0, false));

        return connection.SendAsync(packetWriter);
    }

    readonly record struct PacketInfo(bool Data, ulong Offset, int Length, bool Fin);
}
