using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using SharpQuic.IO;

namespace SharpQuic;

public sealed class QuicStream {
    public ulong Id { get; }

    public bool Client => (Id & 0b01) == 0;

    public bool Server => (Id & 0b01) != 0;

    public bool Bidirectional => (Id & 0b10) == 0;

    public bool Unidirectional => (Id & 0b10) != 0;

    readonly QuicConnection connection;

    readonly CutInputStream inputStream = new(1 << 20);

    readonly CutOutputStream outputStream = new(1 << 20);

    readonly Dictionary<uint, PacketInfo> packets = [];

    readonly PacketWriter packetWriter;

    readonly FrameWriter frameWriter = new();

    readonly SemaphoreSlim maxDataSemaphore = new(0, 1);

    readonly SemaphoreSlim availableSemaphore = new(0, 1);

    ulong offset;

    ulong peerMaxData;

    ulong sentMaxData = 1 << 20;

    bool closed;

    bool peerClosed;

    internal QuicStream(QuicConnection connection, ulong id, ulong peerMaxData) {
        this.connection = connection;
        this.peerMaxData = peerMaxData;
        Id = id;

        packetWriter = new(connection);

        inputStream.MaxDataIncreased += () => {
            if(peerClosed)
                return Task.CompletedTask;

            if(inputStream.MaxData - sentMaxData < 1200)
                return Task.CompletedTask;

            sentMaxData = inputStream.MaxData;

            return SendMaxData().AsTask();
        };
    }

    public async Task WriteAsync(ReadOnlyMemory<byte> data, bool close = false) {
        if(closed)
            throw new QuicException();

        if(outputStream.Available >= data.Length && outputStream.MaxData - this.offset + (ulong)data.Length < 1200) {
            outputStream.Write(data.Span);
            return;
        }

        int position = 0;

        ulong offset = this.offset;

        ulong maxOffset = this.offset + (ulong)data.Length;
        
        while(offset < maxOffset) {
            if((offset >= outputStream.MaxData || outputStream.Available > 0) && position < data.Length) {
                if(outputStream.Available < 1)
                    await availableSemaphore.WaitAsync(connection.connectionSource.Token);

                int writeLength = Math.Min(outputStream.Available, data.Length - position);

                outputStream.Write(data.Span.Slice(position, writeLength));

                position += writeLength;
            }

            int length = Math.Min(1200, Math.Min((int)(peerMaxData - offset), (int)(outputStream.MaxData - offset)));

            if(length > 0) {
                ulong sendOffset = offset + (ulong)length;

                await SendStreamAsync(offset, length, close && sendOffset >= maxOffset);

                offset = sendOffset;
            } else {
                if(peerMaxData <= offset)
                    await maxDataSemaphore.WaitAsync(connection.connectionSource.Token);
                else
                    throw new UnreachableException("Test?"); // TODO remove
            }
        }

        this.offset = maxOffset;

        Console.WriteLine($"Stream Write {data.Length}");

        closed = close;
    }

    public ValueTask<int> FlushAsync() {
        ulong length = outputStream.MaxData - this.offset;

        if(length < 1)
            return ValueTask.FromResult(0);

        ulong offset = this.offset;

        this.offset += length;

        return SendStreamAsync(offset, (int)length, closed);
    }

    public async Task ReadAsync(Memory<byte> memory) {
        await inputStream.ReadAsync(memory, connection.connectionSource.Token);

        CheckClosed();
    }

    internal void Put(ReadOnlySpan<byte> data, ulong offset, bool close) {
        peerClosed |= close;

        inputStream.Write(data, offset);
    }

    internal void MaxStreamData(ulong maxStreamData) {
        if(maxStreamData <= peerMaxData)
            return;

        peerMaxData = maxStreamData;

        Console.WriteLine($"READ MAXDATA TO {maxStreamData}");

        if(maxDataSemaphore.CurrentCount < 1)
            maxDataSemaphore.Release();
    }

    internal void PacketAck(uint number) {
        packets.Remove(number, out PacketInfo packet);

        if(!packet.Data)
            return;

        Console.WriteLine($"STREAM CONFIRM {number}");

        outputStream.Confirm(packet.Offset, (ulong)packet.Length);

        if(outputStream.Available > 0 && availableSemaphore.CurrentCount < 1)
            availableSemaphore.Release();

        CheckClosed();
    }

    internal ValueTask<int> PacketLostAsync(uint number) {
        packets.Remove(number, out PacketInfo info);

        if(!info.Data)
            return SendMaxData();

        return SendStreamAsync(info.Offset, info.Length, info.Fin);
    }

    ValueTask<int> SendStreamAsync(ulong offset, int length, bool fin) {
        Span<byte> data = stackalloc byte[length];

        outputStream.Read(data, offset);

        frameWriter.WriteStream(data, Id, offset, fin);

        Console.WriteLine($"WRITE STREAM TO {offset + (ulong)length}");

        frameWriter.WritePaddingUntil(1200);

        uint number = connection.applicationStage.GetNextPacketNumber(Id);

        packetWriter.Write(PacketType.OneRtt, number, frameWriter.ToPayload(), null);

        packets.Add(number, new(true, offset, data.Length, fin));

        return connection.SendAsync(packetWriter);
    }

    ValueTask<int> SendMaxData() {
        frameWriter.WriteMaxStreamData(Id, inputStream.MaxData);

        frameWriter.WritePaddingUntil(20);

        uint number = connection.applicationStage.GetNextPacketNumber(Id);

        packetWriter.Write(PacketType.OneRtt, number, frameWriter.ToPayload(), null);

        packets.Add(number, new(false, 0, 0, false));

        return connection.SendAsync(packetWriter);
    }

    void CheckClosed() {
        if(closed && peerClosed && inputStream.Offset >= offset && outputStream.Offset >= offset)
            connection.StreamClosed(Id);
    }

    internal void Dispose() {
        inputStream.Dispose();

        maxDataSemaphore.Dispose();
        availableSemaphore.Dispose();
    }

    readonly record struct PacketInfo(bool Data, ulong Offset, int Length, bool Fin);
}
