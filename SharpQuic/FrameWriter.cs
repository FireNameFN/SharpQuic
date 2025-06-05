using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

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

    public void WritePing() {
        Serializer.WriteVariableLength(stream, (ulong)FrameType.Ping);
    }

    public void WriteAck(SortedSet<uint> acks) {
        //foreach(uint ack in acks)
        //    Console.WriteLine($"ACK {ack}");

        //Console.WriteLine($"Acks {acks.Count}");

        List<(uint Gap, uint Length)> ranges = [];

        uint first = acks.Max;
        uint prev = acks.Max + 1;
        uint gap = 0;

        foreach(uint ack in acks.Reverse()) {
            if(ack == prev - 1) {
                prev = ack;
                continue;
            }

            ranges.Add((gap, first - prev));

            gap = prev - ack - 2;

            first = ack;
            prev = ack;
        }

        ranges.Add((gap, first - prev));

        Serializer.WriteVariableLength(stream, (ulong)FrameType.Ack);
        Serializer.WriteVariableLength(stream, acks.Max);
        Serializer.WriteVariableLength(stream, 0);
        Serializer.WriteVariableLength(stream, (ulong)ranges.Count - 1);
        Serializer.WriteVariableLength(stream, ranges[0].Length);

        foreach((uint rangeGap, uint rangeLength) in ranges.Skip(1)) {
            Serializer.WriteVariableLength(stream, rangeGap);
            Serializer.WriteVariableLength(stream, rangeLength);
        }
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

    public void WriteMaxStreams(bool bidirectional, ulong maxStreams) {
        Serializer.WriteVariableLength(stream, (ulong)(bidirectional ? FrameType.MaxStreamsBidirectional : FrameType.MaxStreamsUnidirectional));

        Serializer.WriteVariableLength(stream, maxStreams);
    }

    public void WriteConnectionClose(ulong errorCode, ulong frameType, ReadOnlySpan<char> reasonPhrase) {
        Serializer.WriteVariableLength(stream, (ulong)FrameType.ConnectionClose);

        Serializer.WriteVariableLength(stream, errorCode);

        Serializer.WriteVariableLength(stream, frameType);

        Span<byte> span = stackalloc byte[Encoding.UTF8.GetMaxByteCount(reasonPhrase.Length)];

        int length = Encoding.UTF8.GetBytes(reasonPhrase, span);

        Serializer.WriteVariableLength(stream, (ulong)length);

        stream.Write(span[..length]);
    }

    public void WriteConnectionClose(ulong errorCode, ReadOnlySpan<char> reasonPhrase) {
        Serializer.WriteVariableLength(stream, (ulong)FrameType.ConnectionClose2);

        Serializer.WriteVariableLength(stream, errorCode);

        Span<byte> span = stackalloc byte[Encoding.UTF8.GetMaxByteCount(reasonPhrase.Length)];

        int length = Encoding.UTF8.GetBytes(reasonPhrase, span);

        Serializer.WriteVariableLength(stream, (ulong)length);

        stream.Write(span[..length]);
    }

    public void WriteHandshakeDone() {
        Serializer.WriteVariableLength(stream, (ulong)FrameType.HandshakeDone);
    }
}
