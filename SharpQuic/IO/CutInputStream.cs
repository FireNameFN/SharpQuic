using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace SharpQuic.IO;

public sealed class CutInputStream(int bufferLength) {
    readonly byte[] buffer = new byte[bufferLength];

    readonly List<(ulong Min, ulong Max)> regions = [];

    readonly SemaphoreSlim readSemaphore = new(0, 1);

    readonly SemaphoreSlim semaphore = new(1, 1);

    public ulong Offset { get; private set; }

    public ulong MaxData => Offset + (ulong)buffer.Length;

    public int Length => regions.Count > 0 && regions[0].Min <= Offset ? (int)(regions[0].Max - Offset) : 0;

    public event Func<Task> MaxDataIncreased;

    public void Write(ReadOnlySpan<byte> data, ulong offset) {
        semaphore.Wait();

        if(offset < Offset) {
            int length = (int)(Offset - offset);

            if(data.Length < length)
                return;

            data = data[length..];

            offset = Offset;
        }

        if(Offset + (ulong)buffer.Length < offset + (ulong)data.Length)
            throw new OverflowException();

        data.CopyTo(buffer.AsSpan()[(int)(offset - Offset)..]);

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

    public async Task ReadAsync(Memory<byte> memory, CancellationToken cancellationToken = default) {
        int memoryOffset = 0;

        while(memoryOffset < memory.Length) {
            await readSemaphore.WaitAsync(cancellationToken);

            await semaphore.WaitAsync(cancellationToken);

            int length = Math.Min(memory.Length, (int)(regions[0].Max - Offset));

            buffer[..length].CopyTo(memory[memoryOffset..]);

            memoryOffset += length;

            Offset += (ulong)length;

            buffer.AsSpan()[length..].CopyTo(buffer);

            if(regions[0].Max <= Offset) {
                regions.RemoveAt(0);

                if(readSemaphore.CurrentCount > 0)
                    await readSemaphore.WaitAsync(cancellationToken);
            } else if(readSemaphore.CurrentCount < 1)
                readSemaphore.Release();

            semaphore.Release();

            if(MaxDataIncreased is not null)
                await Task.WhenAll(MaxDataIncreased.GetInvocationList().Select(subscriber => ((Func<Task>)subscriber).Invoke()));
        }
    }

    public int ReadWithoutAdvance(Span<byte> span, ulong offset) {
        if(offset < Offset)
            return 0;

        if(regions[0].Min > Offset)
            return 0;

        int length = Math.Min(span.Length, (int)(regions[0].Max - offset));

        buffer.AsSpan().Slice((int)(offset - Offset), length).CopyTo(span);

        return length;
    }

    public void AdvanceTo(ulong offset) {
        buffer.AsSpan()[(int)(offset-Offset)..].CopyTo(buffer);

        Offset = offset;

        regions.RemoveAll(region => region.Max <= offset);
    }
}
