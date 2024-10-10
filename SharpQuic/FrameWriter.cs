using System;
using System.Collections.Generic;
using System.IO;
using SharpQuic.Tls;

namespace SharpQuic;

public sealed class FrameWriter : IFragmentWriter {
    readonly MemoryStream stream = new();

    readonly SortedSet<uint> acks = [];

    public void Ack(uint packetNumber) {
        acks.Add(packetNumber);
    }

    public byte[] ToPayload() {
        if(acks.Count > 0) {
            WriteAck(acks);
            acks.Clear();
        }

        WritePaddingUntil(20);

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

    public void WriteCrypto(ReadOnlySpan<byte> span) {
        Serializer.WriteVariableLength(stream, (ulong)FrameType.Crypto);

        Serializer.WriteVariableLength(stream, 0);

        Serializer.WriteVariableLength(stream, (ulong)span.Length);

        stream.Write(span);
    }

    public void WriteAck(SortedSet<uint> acks) {
        uint count = 1;

        MemoryStream rangeStream = new();

        uint gap = 0;

        uint length = 0;

        uint previous = acks.Max + 1;

        foreach(uint ack in acks.Reverse()) {
            gap = previous - ack - 1;
            
            if(gap > 0) {
                Serializer.WriteVariableLength(rangeStream, gap);
                Serializer.WriteVariableLength(rangeStream, length);

                length = 0;
                count++;
            }

            length++;
        }

        Serializer.WriteVariableLength(rangeStream, gap);
        Serializer.WriteVariableLength(rangeStream, length);

        Serializer.WriteVariableLength(stream, (ulong)FrameType.Ack);

        Serializer.WriteVariableLength(stream, acks.Max);

        Serializer.WriteVariableLength(stream, 0);

        Serializer.WriteVariableLength(stream, count);

        Serializer.WriteVariableLength(stream, acks.Max - acks.Min);

        rangeStream.Position = 0;
        rangeStream.CopyTo(stream);
    }

    void IFragmentWriter.WriteFragment(ReadOnlySpan<byte> fragment) {
        WriteCrypto(fragment);
    }
}
