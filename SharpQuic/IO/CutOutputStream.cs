using System;
using System.Collections.Generic;
using System.Threading;

namespace SharpQuic.IO;

public sealed class CutOutputStream(int bufferLength) {
    readonly byte[] buffer = new byte[bufferLength];

    readonly List<(ulong Min, ulong Max)> regions = [];

    public ulong Offset { get; private set; }

    public int Fill { get; private set; }

    public ulong MaxData => Offset + (ulong)Fill;

    public int Available => buffer.Length - Fill;

    readonly SemaphoreSlim semaphore = new(1, 1);

    public void Write(ReadOnlySpan<byte> data) {
        semaphore.Wait();

        try {
            if(Fill + data.Length > buffer.Length)
                throw new OverflowException();

            data.CopyTo(buffer.AsSpan()[Fill..]);

            Fill += data.Length;
        } finally {
            semaphore.Release();
        }
    }

    public void Read(Span<byte> destination, ulong offset) {
        semaphore.Wait();
        
        try {
            if(offset < Offset || offset + (ulong)destination.Length > Offset + (ulong)Fill)
                throw new IndexOutOfRangeException();

            buffer.AsSpan().Slice((int)(offset - Offset), destination.Length).CopyTo(destination);
        } finally {
            semaphore.Release();
        }
    }

    public void Confirm(ulong offset, ulong length) {
        ulong max = offset + length;

        semaphore.Wait();

        try {
            if(max <= Offset)
                return;

            bool inserted = false;

            for(int i = 0; i < regions.Count; i++) {
                if(regions[i].Min < offset)
                    continue;

                regions.Insert(i, (offset, max));

                inserted = true;
                
                break;
            }

            if(!inserted)
                regions.Add((offset, max));

            if(offset > Offset)
                return;

            ulong prevOffset = Offset;

            int removeCount = 0;

            for(int i = 0; i < regions.Count; i++) {
                if(regions[i].Min > Offset)
                    break;

                Offset = Math.Max(Offset, regions[i].Max);

                removeCount = i;
            }

            regions.RemoveRange(0, removeCount);

            int advance = (int)(Offset - prevOffset);

            buffer.AsSpan()[advance..Fill].CopyTo(buffer);

            Fill -= advance;
        } finally {
            semaphore.Release();
        }
    }
}
