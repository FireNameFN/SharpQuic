using System;
using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;

namespace SharpQuic;

public static class Serializer {
    public static void WriteByte(Stream stream, byte value) {
        stream.Write([value]);
    }

    public static void WriteUInt16(Stream stream, ushort value) {
        Span<byte> span = stackalloc byte[sizeof(ushort)];

        BinaryPrimitives.WriteUInt16BigEndian(span, value);

        stream.Write(span);
    }

    public static void WriteUInt32(Stream stream, uint value) {
        Span<byte> span = stackalloc byte[sizeof(uint)];

        BinaryPrimitives.WriteUInt32BigEndian(span, value);

        stream.Write(span);
    }

    public static void WriteWithLength(Stream stream, uint value, int length) {
        Span<byte> span = stackalloc byte[sizeof(uint)];

        BinaryPrimitives.WriteUInt32BigEndian(span, value);

        stream.Write(span[^length..]);
    }

    public static int GetVariableLength(ulong value) {
        return value switch {
            < 1 << 6 => 1,
            < 1 << 14 => 2,
            < 1 << 30 => 4,
            < 1ul << 62 => 8,
            _ => throw new ArgumentOutOfRangeException(nameof(value))
        };
    }

    public static void WriteVariableLength(Stream stream, ulong value, int length = 0) {
        int bits;

        if(length < 1)
            (bits, length) = value switch {
                < 1 << 6 => (0b00 << 6, 1),
                < 1 << 14 => (0b01 << 6, 2),
                < 1 << 30 => (0b10 << 6, 4),
                < 1ul << 62 => (0b11 << 6, 8),
                _ => throw new ArgumentOutOfRangeException(nameof(value))
            };
        else
            bits = length switch {
                1 => 0b00 << 6,
                2 => 0b01 << 6,
                3 => 0b10 << 6,
                4 => 0b11 << 6,
                _ => throw new ArgumentOutOfRangeException(nameof(length))
            };

        Span<byte> span = stackalloc byte[sizeof(ulong)];

        BinaryPrimitives.WriteUInt64BigEndian(span, value);

        span[^length] = (byte)(span[^length] | bits);

        stream.Write(span[^length..]);
    }

    public static byte ReadByte(Stream stream) {
        Span<byte> span = stackalloc byte[sizeof(byte)];

        stream.ReadExactly(span);

        return span[0];
    }

    public static ushort ReadUInt16(Stream stream) {
        Span<byte> span = stackalloc byte[sizeof(ushort)];

        stream.ReadExactly(span);

        return BinaryPrimitives.ReadUInt16BigEndian(span);
    }

    public static uint ReadUInt32(Stream stream) {
        Span<byte> span = stackalloc byte[sizeof(uint)];

        stream.ReadExactly(span);

        return BinaryPrimitives.ReadUInt32BigEndian(span);
    }

    public static uint ReadWithLength(Stream stream, int length) {
        Span<byte> span = stackalloc byte[sizeof(uint)];

        stream.ReadExactly(span[^length..]);

        return BinaryPrimitives.ReadUInt32BigEndian(span);
    }

    public static (ulong Value, int Length) ReadVariableLength(Stream stream) {
        Span<byte> span = stackalloc byte[sizeof(ulong) + 7];

        stream.ReadExactly(span.Slice(7, 1));

        int length = (span[7] & 0b11000000) switch {
            0b00000000 => 0,
            0b01000000 => 1,
            0b10000000 => 3,
            _ => 7
        };

        span[7] &= 0b00111111;

        if(length > 0)
            stream.ReadExactly(span.Slice(8, length));

        return (BinaryPrimitives.ReadUInt64BigEndian(span.Slice(length, 8)), length + 1);
    }

    public static int GetLength(uint value) {
        return value switch {
            < 1 << 8 => 1,
            < 1 << 16 => 2,
            < 1 << 24 => 3,
            _ => 4
        };
    }
}
