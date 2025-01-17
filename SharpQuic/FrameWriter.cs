using System;
using System.Collections.Generic;
using System.IO;

namespace SharpQuic;

public sealed class FrameWriter {
    readonly MemoryStream stream = new();

    public int Length => (int)stream.Length;

    public bool HasPayload => stream.Length > 0;

    public byte[] ToPayload() {
        byte[] payload = stream.ToArray();

        stream.SetLength(0);

        return payload;
    }

    public void WritePaddingUntil(int length) {
        if(length <= stream.Length)
            return;

        Span<byte> padding = stackalloc byte[length - (int)stream.Position];
        
        stream.Write(padding);
    }

    public void WriteAck(SortedSet<uint> acks) {
        uint count = 0;

        MemoryStream rangeStream = new();

        uint gap = 0;

        uint length = 0;

        uint previous = acks.Max + 1;

        bool ranges = false;

        uint lastBeforeRanges = acks.Max;

        foreach(uint ack in acks)
            Console.WriteLine($"ACK {ack}");

        foreach(uint ack in acks.Reverse()) {
            gap = previous - ack - 1;
            previous = ack;

            if(!ranges) {
                if(gap > 0) {
                    ranges = true;
                    lastBeforeRanges = ack;
                }
                continue;
            }
            
            if(gap > 0) {
                Serializer.WriteVariableLength(rangeStream, gap - 1);
                Serializer.WriteVariableLength(rangeStream, length);

                Console.WriteLine($"ACK Range Gap: {gap}");
                Console.WriteLine($"ACK Range Length: {length}");

                length = 0;
                count++;
            }

            length++;
        }

        if(length > 0) {
            Serializer.WriteVariableLength(rangeStream, gap);
            Serializer.WriteVariableLength(rangeStream, length);

            count++;

            Console.WriteLine($"ACK Range Gap: {gap}");
            Console.WriteLine($"ACK Range Length: {length}");
        }

        Serializer.WriteVariableLength(stream, (ulong)FrameType.Ack);

        Console.WriteLine($"ACK Max: {acks.Max}");

        Serializer.WriteVariableLength(stream, acks.Max);

        Serializer.WriteVariableLength(stream, 0);

        Console.WriteLine($"ACK Range Count: {count}");

        Console.WriteLine($"ACK First: {acks.Max - lastBeforeRanges}");

        Serializer.WriteVariableLength(stream, count);

        Serializer.WriteVariableLength(stream, acks.Max - lastBeforeRanges);

        rangeStream.Position = 0;
        rangeStream.CopyTo(stream);
    }

    public void WriteCrypto(ReadOnlySpan<byte> data, ulong offset) {
        Serializer.WriteVariableLength(stream, (ulong)FrameType.Crypto);

        Serializer.WriteVariableLength(stream, offset);

        Serializer.WriteVariableLength(stream, (ulong)data.Length);

        stream.Write(data);
    }

    public void WriteStream(ReadOnlySpan<byte> data, ulong streamId, ulong offset, bool fin) {
        Serializer.WriteVariableLength(stream, (ulong)(FrameType.Stream | FrameType.StreamOffset | FrameType.StreamLength | (fin ? FrameType.StreamFin : 0)));

        Serializer.WriteVariableLength(stream, streamId);

        Serializer.WriteVariableLength(stream, offset);

        Serializer.WriteVariableLength(stream, (ulong)data.Length);

        stream.Write(data);
    }

    public void WriteMaxStreamData(ulong streamId, ulong maxData) {
        Serializer.WriteVariableLength(stream, (ulong)FrameType.MaxStreamData);

        Serializer.WriteVariableLength(stream, streamId);

        Serializer.WriteVariableLength(stream, maxData);
    }
}
