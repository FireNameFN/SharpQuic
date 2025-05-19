using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using SharpQuic.IO;

namespace SharpQuic;

public sealed class QuicStream {
    public ulong Id { get; }

    readonly QuicConnection connection;

    readonly CutInputStream inputStream = new(1024); // TODO Dispose

    readonly CutOutputStream outputStream = new(512);

    readonly Dictionary<uint, PacketInfo> packets = [];

    readonly PacketWriter packetWriter;

    readonly FrameWriter frameWriter = new();

    ulong offset;

    ulong peerMaxData = 1024;

    readonly SemaphoreSlim maxDataSemaphore = new(0, 1); // TODO Dispose

    readonly SemaphoreSlim availableSemaphore = new(0, 1); // TODO Dispose

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
        int position = 0;

        ulong offset = this.offset;

        ulong maxOffset = this.offset + (ulong)data.Length;
        
        while(offset < maxOffset) {
            if((offset >= outputStream.MaxData || outputStream.Available > 0) && position < data.Length) {
                if(outputStream.Available < 1)
                    await availableSemaphore.WaitAsync(connection.cancellationToken);

                int writeLength = Math.Min(outputStream.Available, data.Length - position);

                outputStream.Write(data.Span.Slice(position, writeLength));

                position += writeLength;
            }

            int length = Math.Min(1200, Math.Min((int)(peerMaxData - offset), (int)(outputStream.MaxData - offset)));

            if(length > 0) {
                await SendStreamAsync(offset, length, false);

                offset += (ulong)length;
            } else {
                if(peerMaxData <= offset)
                    await maxDataSemaphore.WaitAsync(connection.cancellationToken);
                else
                    throw new UnreachableException("Test?");
            }
        }

        this.offset = maxOffset;

        /*int position = 0;

        while(position < data.Length) {
            if((int)(outputStream.MaxData - offset) - position < 1 || outputStream.Available > 0) {
                if(outputStream.Available < 1)
                    await availableSemaphore.WaitAsync();

                outputStream.Write(data.Span[position..Math.Min(outputStream.Available, data.Length - position)]);
            }

            int length = Math.Min(1200, Math.Min((int)(peerMaxData - offset) - position, (int)(outputStream.MaxData - offset) - position));
            
            if(length > 0) {
                await SendStreamAsync(offset + (ulong)position, length, false);

                position += length;
            } else {
                if((int)(peerMaxData - offset) - position < 1)
                    await maxDataSemaphore.WaitAsync();
            }
        }
        
        offset += (ulong)data.Length;*/

        /*int position = 0;

        while(position < data.Length) {
            int length = Math.Min(1200 - frameWriter.Length, (int)(peerMaxData - offset) - position);

            if(position + length > data.Length)
                length = data.Length - position;

            if(length > 0) {
                await SendStreamAsync(data.Slice(position, length).Span, offset + (ulong)position, position + length >= data.Length && close);

                position += length;
            } else
                await semaphore.WaitAsync();
        }

        offset += (ulong)data.Length;*/

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

        if(outputStream.Available > 0)
            availableSemaphore.Release();
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

        //if(connection.applicationStage.acks.Count > 0)
        //    frameWriter.WriteAck([..connection.applicationStage.acks]); // TODO remove ToArray

        frameWriter.WritePaddingUntil(1200);

        uint number = connection.applicationStage.GetNextPacketNumber(Id);

        packetWriter.Write(PacketType.OneRtt, number, frameWriter.ToPayload(), null);

        packets.Add(number, new(true, offset, data.Length, fin));

        return connection.SendAsync(packetWriter);
    }

    ValueTask<int> SendMaxData() {
        frameWriter.WriteMaxStreamData(Id, inputStream.MaxData);

        //if(connection.applicationStage.acks.Count > 0)
        //    frameWriter.WriteAck([..connection.applicationStage.acks]); // TODO remove ToArray

        frameWriter.WritePaddingUntil(20);

        uint number = connection.applicationStage.GetNextPacketNumber(Id);

        packetWriter.Write(PacketType.OneRtt, number, frameWriter.ToPayload(), null);

        packets.Add(number, new(false, 0, 0, false));

        return connection.SendAsync(packetWriter);
    }

    readonly record struct PacketInfo(bool Data, ulong Offset, int Length, bool Fin);
}
