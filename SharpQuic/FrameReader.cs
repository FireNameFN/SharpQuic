using System;
using System.IO;
using System.Text;
using SharpQuic.Frames;

namespace SharpQuic;

public sealed class FrameReader {
    internal MemoryStream stream;

    public Frame Read() {
        FrameType type = (FrameType)Serializer.ReadVariableLength(stream).Value;

        if(type != 0)
            Console.WriteLine($"Frame {type}");

        return type switch {
            0 => null,
            FrameType.Ack => ReadAck(),
            FrameType.Crypto => ReadCrypto(),
            FrameType.NewToken => ReadNewToken(),
            >= FrameType.Stream and <= FrameType.StreamMax => ReadStream(type),
            FrameType.MaxStreams => ReadMaxStreams(),
            FrameType.NewConnectionId => ReadNewConnectionId(),
            FrameType.ConnectionClose => ReadConnectionClose(false),
            FrameType.ConnectionClose2 => ReadConnectionClose(true),
            FrameType.HandshakeDone => new HandshakeDoneFrame(),
            _ => throw new QuicException()
        };
    }

    Frame ReadAck() {
        ulong largest = Serializer.ReadVariableLength(stream).Value;
        ulong delay = Serializer.ReadVariableLength(stream).Value;
        int count = (int)Serializer.ReadVariableLength(stream).Value;
        Serializer.ReadVariableLength(stream);

        for(int i = 0; i < count; i++) {
            Serializer.ReadVariableLength(stream);
            Serializer.ReadVariableLength(stream);
        }

        return new AckFrame();
    }

    Frame ReadCrypto() {
        ulong offset = Serializer.ReadVariableLength(stream).Value;

        ulong length = Serializer.ReadVariableLength(stream).Value;

        byte[] data = new byte[length];

        stream.ReadExactly(data);

        return new CryptoFrame() {
            Offset = offset,
            Length = length,
            Data = data
        };
    }

    Frame ReadNewToken() {
        ulong length = Serializer.ReadVariableLength(stream).Value;

        stream.Position += (long)length;

        return new HandshakeDoneFrame();
    }

    Frame ReadStream(FrameType type) {
        ulong id = Serializer.ReadVariableLength(stream).Value;

        ulong offset = 0;

        ulong length = (ulong)(stream.Length - stream.Position);

        if(type.HasFlag(FrameType.StreamOffset))
            offset = Serializer.ReadVariableLength(stream).Value;
        
        if(type.HasFlag(FrameType.StreamLength))
            length = Serializer.ReadVariableLength(stream).Value;

        byte[] data = new byte[length];

        stream.ReadExactly(data);

        return new StreamFrame() {
            Id = id,
            Offset = offset,
            Length = length,
            Data = data
        };
    }

    Frame ReadMaxStreams() {
        Serializer.ReadVariableLength(stream);

        return new HandshakeDoneFrame();
    }

    Frame ReadNewConnectionId() {
        Serializer.ReadVariableLength(stream);

        Serializer.ReadVariableLength(stream);

        int length = Serializer.ReadByte(stream);

        byte[] connectionId = new byte[length];

        stream.ReadExactly(connectionId);
        
        stream.Position += 16;

        return new NewConnectionIdFrame();
    }

    Frame ReadConnectionClose(bool application) {
        ulong error = Serializer.ReadVariableLength(stream).Value;
        FrameType frameType = 0;
        if(!application)
            frameType = (FrameType)Serializer.ReadVariableLength(stream).Value;
        ulong phraseLength = Serializer.ReadVariableLength(stream).Value;

        Span<byte> phrase = stackalloc byte[(int)phraseLength];

        stream.ReadExactly(phrase);

        Console.WriteLine($"CONNECTION_CLOSE: {error} {frameType} {Encoding.UTF8.GetString(phrase)}");

        throw new QuicException();

        //return new(FrameType.ConnectionClose, null);
    }
}
