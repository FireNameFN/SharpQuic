using System;
using System.Collections.Generic;
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

    public bool CanRead => Connection.endpointType == EndpointType.Client != Client || Bidirectional;

    public bool CanWrite => Connection.endpointType == EndpointType.Client == Client || Bidirectional;

    public QuicConnection Connection { get; }

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
        Connection = connection;
        this.peerMaxData = peerMaxData;
        Id = id;

        if(!CanRead)
            peerClosed = true;
        
        if(!CanWrite)
            closed = true;

        packetWriter = new(connection);

        inputStream.MaxDataIncreased += () => {
            if(peerClosed)
                return Task.CompletedTask;

            if(inputStream.MaxData - sentMaxData < 1200)
                return Task.CompletedTask;

            sentMaxData = inputStream.MaxData;

            return SendMaxStreamData(packetWriter).AsTask();
        };
    }

    public async Task WriteAsync(ReadOnlyMemory<byte> data, bool close = false) {
        if(closed)
            throw new QuicException();

        closed = close;

        int position = 0;

        ulong maxOffset = offset + (ulong)data.Length;
        
        while(offset < maxOffset) {
            if(position < data.Length && (offset >= outputStream.MaxData || outputStream.Available > 0)) {
                if(outputStream.Available < 1)
                    await availableSemaphore.WaitAsync(Connection.connectionSource.Token);

                int writeLength = Math.Min(outputStream.Available, data.Length - position);

                outputStream.Write(data.Span.Slice(position, writeLength));

                position += writeLength;
            }

            if(position >= data.Length && outputStream.MaxData - offset < 1200 && !close)
                return;

            int length = Math.Min(1200, Math.Min((int)(peerMaxData - offset), (int)(outputStream.MaxData - offset)));

            if(length > 0) {
                ulong sendOffset = offset + (ulong)length;

                await SendStreamAsync(packetWriter, offset, length, close && sendOffset >= maxOffset);

                offset = sendOffset;
            } else
                await maxDataSemaphore.WaitAsync(Connection.connectionSource.Token);
        }

        if(Connection.debugLogging)
            Console.WriteLine($"Stream Write {data.Length}");
    }

    public ValueTask<int> FlushAsync(bool close = false) {
        if(closed)
            return ValueTask.FromResult(0);

        ulong length = outputStream.MaxData - this.offset;

        if(length < 1) {
            if(close)
                return SendStreamAsync(packetWriter, this.offset, 0, true);

            return ValueTask.FromResult(0);
        }

        closed |= close;

        ulong offset = this.offset;

        this.offset += length;

        return SendStreamAsync(packetWriter, offset, (int)length, closed);
    }

    public ValueTask<int> CloseAsync() {
        if(closed)
            return ValueTask.FromResult(0);

        return SendStreamAsync(packetWriter, offset, 0, true);
    }

    public async Task ReadAsync(Memory<byte> memory) {
        await inputStream.ReadAsync(memory, Connection.connectionSource.Token);

        CheckClosed(packetWriter);
    }

    internal async Task PutAsync(ReadOnlyMemory<byte> data, ulong offset, bool close) {
        await inputStream.WriteAsync(data, offset);

        peerClosed |= close;
    }

    internal void MaxStreamData(ulong maxStreamData) {
        if(maxStreamData <= peerMaxData)
            return;

        peerMaxData = maxStreamData;

        if(Connection.debugLogging)
            Console.WriteLine($"READ MAXDATA TO {maxStreamData}");

        if(maxDataSemaphore.CurrentCount < 1)
            maxDataSemaphore.Release();
    }

    internal void PacketAck(PacketWriter packetWriter, uint number) {
        packets.Remove(number, out PacketInfo packet);

        if(!packet.Data)
            return;

        if(Connection.debugLogging)
            Console.WriteLine($"STREAM CONFIRM {number}");

        outputStream.Confirm(packet.Offset, (ulong)packet.Length);

        if(outputStream.Available > 0 && availableSemaphore.CurrentCount < 1)
            availableSemaphore.Release();

        CheckClosed(packetWriter);
    }

    internal ValueTask<int> PacketLostAsync(PacketWriter packetWriter, uint number) {
        packets.Remove(number, out PacketInfo info);

        if(!info.Data)
            return SendMaxStreamData(packetWriter);

        return SendStreamAsync(packetWriter, info.Offset, info.Length, info.Fin);
    }

    ValueTask<int> SendStreamAsync(PacketWriter packetWriter, ulong offset, int length, bool fin) {
        Span<byte> data = stackalloc byte[length];

        outputStream.Read(data, offset);

        frameWriter.WriteStream(data, Id, offset, fin);

        if(Connection.debugLogging)
            Console.WriteLine($"WRITE STREAM TO {offset + (ulong)length}");

        frameWriter.WritePaddingUntil(20);

        uint number = Connection.applicationStage.GetNextPacketNumber(Id);

        packetWriter.Write(PacketType.OneRtt, number, frameWriter.ToPayload(), null);

        packets.Add(number, new(true, offset, length, fin));

        return Connection.SendAsync(packetWriter);
    }

    ValueTask<int> SendMaxStreamData(PacketWriter packetWriter) {
        frameWriter.WriteMaxStreamData(Id, inputStream.MaxData);

        frameWriter.WritePaddingUntil(20);

        uint number = Connection.applicationStage.GetNextPacketNumber(Id);

        packetWriter.Write(PacketType.OneRtt, number, frameWriter.ToPayload(), null);

        packets.Add(number, new(false, 0, 0, false));

        return Connection.SendAsync(packetWriter);
    }

    void CheckClosed(PacketWriter packetWriter) {
        if(closed && peerClosed && inputStream.Empty && outputStream.Offset >= offset)
            Connection.StreamClosed(packetWriter, Id);
    }

    internal void Dispose() {   
        if(Connection.debugLogging)
            Console.WriteLine($"STREAM {Id} DISPOSE");

        inputStream.Dispose();

        maxDataSemaphore.Dispose();
        availableSemaphore.Dispose();
    }

    readonly record struct PacketInfo(bool Data, ulong Offset, int Length, bool Fin);
}
