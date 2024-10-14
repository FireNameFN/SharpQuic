using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace SharpQuic;

public sealed class CutStream(int bufferLength) {
    readonly byte[] buffer = new byte[bufferLength];

    readonly List<(ulong Min, ulong Max)> regions = [];

    ulong offset;

    readonly SemaphoreSlim readSemaphore = new(0, 1);

    readonly SemaphoreSlim semaphore = new(1, 1);

    public ulong MaxData => offset + (ulong)buffer.Length;

    public void Write(ReadOnlySpan<byte> data, ulong offset) {
        semaphore.Wait();

        if(offset < this.offset) {
            int length = (int)(this.offset - offset);

            if(data.Length < length)
                return;

            data = data[length..];

            offset = this.offset;
        }

        if(this.offset + (ulong)buffer.Length < offset + (ulong)data.Length)
            throw new OverflowException();

        data.CopyTo(buffer.AsSpan()[(int)(offset - this.offset)..]);

        (ulong, ulong) region = new(offset, offset + (ulong)data.Length);

        bool inserted = false;

        for(int i = 0; i < regions.Count; i++)
            if(regions[i].Min > offset) {
                regions.Insert(i, region);
                inserted = true;
                break;
            }

        if(!inserted)
            regions.Add(region);

        for(int i = 0; i < regions.Count - 1; i++)
            if(regions[i+1].Min <= regions[i].Max) {
                regions[i] = new(regions[i].Min, Math.Max(regions[i].Max, regions[i+1].Max));

                regions.RemoveAt(i+1);

                i--;
            }

        if(regions[0].Min == offset && readSemaphore.CurrentCount < 1)
            readSemaphore.Release();

        semaphore.Release();
    }

    public async Task ReadAsync(Memory<byte> memory) {
        int memoryOffset = 0;

        while(memoryOffset < memory.Length) {
            await readSemaphore.WaitAsync();

            await semaphore.WaitAsync();

            int length = Math.Min(memory.Length, (int)(regions[0].Max - offset));

            buffer[..length].CopyTo(memory[memoryOffset..]);

            memoryOffset += length;

            offset += (ulong)length;

            buffer.AsSpan()[length..].CopyTo(buffer);

            if(offset >= regions[0].Max) {
                regions.RemoveAt(0);

                if(readSemaphore.CurrentCount > 0)
                    readSemaphore.Wait();
            } else if(readSemaphore.CurrentCount < 1)
                readSemaphore.Release();

            semaphore.Release();
        }
    }
}
