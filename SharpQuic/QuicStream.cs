using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using SharpQuic.IO;

namespace SharpQuic;

public sealed class QuicStream {
    public ulong Id { get; }

    public bool Client => (Id & 0b01) == 0;

    public bool Server => (Id & 0b01) != 0;

    public bool Bidirectional => (Id & 0b10) == 0;

    public bool Unidirectional => (Id & 0b10) != 0;

    public bool Inside => Connection.endpointType == EndpointType.Client == Client;

    public bool Outside => Connection.endpointType == EndpointType.Client != Client;

    public bool CanRead => Outside || Bidirectional;

    public bool CanWrite => Inside || Bidirectional;

    public QuicConnection Connection { get; }

    readonly CutInputStream inputStream = new(1 << 20);

    readonly CutOutputStream outputStream = new(1 << 20);

    readonly Dictionary<uint, PacketInfo> packets = [];

    readonly PacketWriter packetWriter;

    readonly SemaphoreSlim maxDataSemaphore = new(0, 1);

    readonly SemaphoreSlim availableSemaphore = new(0, 1);

    readonly SemaphoreSlim outputSemaphore = new(1, 1);

    readonly Channel<PacketInfo> lostPackets = Channel.CreateUnbounded<PacketInfo>(new() { SingleReader = true, SingleWriter = true });

    ulong offset;

    ulong peerMaxData;

    ulong sentMaxData = 1 << 20;

    bool closed;

    bool peerClosed;

    bool declaredOpen;

    internal QuicStream(QuicConnection connection, ulong id, ulong peerMaxData) {
        Connection = connection;
        Id = id;
        this.peerMaxData = peerMaxData;

        peerClosed = !CanRead;
        
        closed = !CanWrite;

        declaredOpen = Outside;

        packetWriter = new(connection);

        inputStream.MaxDataIncreased += () => {
            if(peerClosed)
                return Task.CompletedTask;

            if(inputStream.MaxData - sentMaxData < 1200)
                return Task.CompletedTask;

            sentMaxData = inputStream.MaxData;

            return SendMaxStreamData(packetWriter).AsTask();
        };

        Task.Run(Runner);
    }

    async Task Runner() {
        PacketWriter packetWriter = new(Connection);

        while(await lostPackets.Reader.WaitToReadAsync()) {
            PacketInfo packet = await lostPackets.Reader.ReadAsync();

            if(!packet.Data)
                await SendMaxStreamData(packetWriter).AsTask();
            else
                await SendStreamAsync(packetWriter, packet.Offset, packet.Length, packet.Fin);
        }
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

                declaredOpen = true;

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
            } else if(!declaredOpen) {
                await SendStreamAsync(packetWriter, 0, 0, false);

                declaredOpen = true;
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

        CheckClosed();
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

    internal void PacketAck(uint number) {
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

        CheckClosed();
    }

    internal ValueTask PacketLostAsync(uint number) {
        PacketInfo packet;

        lock(packets)
            packets.Remove(number, out packet);

        //if(!packet.Data)
        //    return SendMaxStreamData(packetWriter).AsTask();

        //return SendStreamAsync(packetWriter, packet.Offset, packet.Length, packet.Fin);

        return lostPackets.Writer.WriteAsync(packet);
    }

    async Task SendStreamAsync(PacketWriter packetWriter, ulong offset, int length, bool fin) {
        byte[] data = new byte[length]; // TODO .NET 9

        outputSemaphore.Wait(Connection.connectionSource.Token);
        outputStream.Read(data, offset);
        outputSemaphore.Release();

        packetWriter.FrameWriter.WriteStream(data, Id, offset, fin);

        packetWriter.FrameWriter.WritePaddingUntil(20);

        uint number = Connection.applicationStage.GetNextPacketNumber(Id);

        if(Connection.debugLogging)
            Console.WriteLine($"WRITE STREAM {number} TO {offset + (ulong)length}");

        int dataLength = packetWriter.Write(PacketType.OneRtt, number, null);

        await Connection.applicationStage.WaitForCongestion(dataLength);

        Connection.applicationStage.AddInFlightPacket(number, true, dataLength);

        lock(packets)
            packets.Add(number, new(true, offset, length, fin));

        await Connection.SendAsync(packetWriter);
    }

    ValueTask<int> SendMaxStreamData(PacketWriter packetWriter) {
        packetWriter.FrameWriter.WriteMaxStreamData(Id, inputStream.MaxData);

        packetWriter.FrameWriter.WritePaddingUntil(20);

        uint number = Connection.applicationStage.GetNextPacketNumber(Id);

        int dataLength = packetWriter.Write(PacketType.OneRtt, number, null);

        Connection.applicationStage.AddInFlightPacket(number, true, dataLength);

        lock(packets)
            packets.Add(number, new(false, 0, 0, false));

        return Connection.SendAsync(packetWriter);
    }

    void CheckClosed() {
        if(closed && peerClosed && inputStream.Empty && outputStream.Offset >= offset)
            Connection.StreamClosed(Id);
    }

    internal void Dispose() {
        if(Connection.debugLogging)
            Console.WriteLine($"STREAM {Id} DISPOSE");

        lostPackets.Writer.Complete();

        inputStream.Dispose();

        maxDataSemaphore.Dispose();
        availableSemaphore.Dispose();
        outputSemaphore.Dispose();
    }

    readonly record struct PacketInfo(bool Data, ulong Offset, int Length, bool Fin);
}
