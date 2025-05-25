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

    readonly CutOutputStream outputStream = new(1 << 12);

    readonly Dictionary<uint, PacketInfo> packets = [];

    readonly PacketWriter packetWriter;

    readonly SemaphoreSlim maxDataSemaphore = new(0, 1);

    readonly SemaphoreSlim availableSemaphore = new(0, 1);

    readonly SemaphoreSlim outputSemaphore = new(1, 1);

    ulong offset;

    ulong peerMaxData;

    ulong sentMaxData = 1 << 20;

    bool closed;

    bool peerClosed;

    internal QuicStream(QuicConnection connection, ulong id, ulong peerMaxData) {
        Connection = connection;
        Id = id;
        this.peerMaxData = peerMaxData;

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

        int position = 0;

        ulong maxOffset = offset + (ulong)data.Length;
        
        while(offset < maxOffset || position < data.Length) {
            await outputSemaphore.WaitAsync(Connection.connectionSource.Token);

            if(position < data.Length && (offset >= outputStream.MaxData || outputStream.Available > 0)) {
                if(outputStream.Available < 1) {
                    outputSemaphore.Release();
                    await availableSemaphore.WaitAsync(Connection.connectionSource.Token);
                    await outputSemaphore.WaitAsync(Connection.connectionSource.Token);
                }

                int writeLength = Math.Min(outputStream.Available, data.Length - position);

                outputStream.Write(data.Span.Slice(position, writeLength));

                position += writeLength;
            }

            if(position >= data.Length && outputStream.MaxData - offset < 1200 && !close) {
                outputSemaphore.Release();
                return;
            }

            int length = Math.Min(1200, Math.Min((int)(peerMaxData - offset), (int)(outputStream.MaxData - offset)));

            if(length > 0) {
                ulong sendOffset = offset + (ulong)length;

                outputSemaphore.Release();
                await SendStreamAsync(packetWriter, offset, length, close && sendOffset >= maxOffset);
                await outputSemaphore.WaitAsync(Connection.connectionSource.Token);

                offset = sendOffset;
            } else if(peerMaxData - offset < 1) {
                outputSemaphore.Release();
                await maxDataSemaphore.WaitAsync(Connection.connectionSource.Token);
                await outputSemaphore.WaitAsync(Connection.connectionSource.Token);
            }

            outputSemaphore.Release();
        }

        closed = close;

        if(Connection.debugLogging)
            Console.WriteLine($"Stream Write {data.Length}");
    }

    public async ValueTask FlushAsync(bool close = false) {
        if(closed)
            return;

        outputSemaphore.Wait(Connection.connectionSource.Token);

        ulong length = outputStream.MaxData - this.offset;

        outputSemaphore.Release();

        if(length < 1) {
            if(close) {
                await SendStreamAsync(packetWriter, this.offset, 0, true);

                closed = true;
            }

            return;
        }

        ulong offset = this.offset;

        this.offset += length;

        await SendStreamAsync(packetWriter, offset, (int)length, close);

        closed = close;
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
        PacketInfo packet;

        lock(packets)
            packets.Remove(number, out packet);

        if(!packet.Data)
            return;

        if(Connection.debugLogging)
            Console.WriteLine($"STREAM CONFIRM {number}");

        outputSemaphore.Wait(Connection.connectionSource.Token);

        outputStream.Confirm(packet.Offset, (ulong)packet.Length);

        if(outputStream.Available > 0 && availableSemaphore.CurrentCount < 1)
            availableSemaphore.Release();

        outputSemaphore.Release();

        CheckClosed(packetWriter);
    }

    internal ValueTask<int> PacketLostAsync(PacketWriter packetWriter, uint number) {
        PacketInfo packet;

        lock(packets)
            packets.Remove(number, out packet);

        if(!packet.Data)
            return SendMaxStreamData(packetWriter);

        return SendStreamAsync(packetWriter, packet.Offset, packet.Length, packet.Fin);
    }

    ValueTask<int> SendStreamAsync(PacketWriter packetWriter, ulong offset, int length, bool fin) {
        Span<byte> data = stackalloc byte[length];

        outputSemaphore.Wait(Connection.connectionSource.Token);
        outputStream.Read(data, offset);
        outputSemaphore.Release();

        packetWriter.FrameWriter.WriteStream(data, Id, offset, fin);

        if(Connection.debugLogging)
            Console.WriteLine($"WRITE STREAM TO {offset + (ulong)length}");

        packetWriter.FrameWriter.WritePaddingUntil(20);

        uint number = Connection.applicationStage.GetNextPacketNumber(Id, packetWriter == this.packetWriter);

        packetWriter.Write(PacketType.OneRtt, number, null);

        lock(packets)
            packets.Add(number, new(true, offset, length, fin));

        return Connection.SendAsync(packetWriter);
    }

    ValueTask<int> SendMaxStreamData(PacketWriter packetWriter) {
        packetWriter.FrameWriter.WriteMaxStreamData(Id, inputStream.MaxData);

        packetWriter.FrameWriter.WritePaddingUntil(20);

        uint number = Connection.applicationStage.GetNextPacketNumber(Id, packetWriter == this.packetWriter);

        packetWriter.Write(PacketType.OneRtt, number, null);

        lock(packets)
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
        outputSemaphore.Dispose();
    }

    readonly record struct PacketInfo(bool Data, ulong Offset, int Length, bool Fin);
}
