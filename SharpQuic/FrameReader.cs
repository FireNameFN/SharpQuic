using System.IO;

namespace SharpQuic;

public sealed class FrameReader {
    internal MemoryStream stream;

    public Frame Read() {
        FrameType type = (FrameType)Serializer.ReadVariableLength(stream).Value;

        return type switch {
            0 => new(0, null),
            FrameType.Ack => ReadAck(),
            FrameType.Crypto => ReadCrypto(),
            > FrameType.Stream and < FrameType.StreamMax => ReadStream(type),
            FrameType.ConnectionClose => ReadConnectionClose(),
            FrameType.ConnectionClose2 => ReadConnectionClose(),
            _ => throw new QuicException()
        };
    }

    Frame ReadAck() {
        Serializer.ReadVariableLength(stream);
        Serializer.ReadVariableLength(stream);
        int count = (int)Serializer.ReadVariableLength(stream).Value;
        Serializer.ReadVariableLength(stream);

        for(int i = 0; i < count; i++) {
            Serializer.ReadVariableLength(stream);
            Serializer.ReadVariableLength(stream);
        }

        return new(FrameType.Ack, null);
    }

    Frame ReadCrypto() {
        Serializer.ReadVariableLength(stream);

        ulong length = Serializer.ReadVariableLength(stream).Value;

        byte[] data = new byte[length];

        stream.ReadExactly(data);

        return new(FrameType.Crypto, data);
    }

    Frame ReadStream(FrameType type) {
        ulong id = Serializer.ReadVariableLength(stream).Value;

        ulong offset;

        ulong length = 0;

        if(type.HasFlag(FrameType.StreamOffset))
            offset = Serializer.ReadVariableLength(stream).Value;
        
        if(type.HasFlag(FrameType.StreamLength))
            length = Serializer.ReadVariableLength(stream).Value;

        byte[] data = new byte[length > 0 ? (int)length : (stream.Length - stream.Position)];

        stream.ReadExactly(data);

        return new(type, data);
    }

    Frame ReadConnectionClose() {
        ulong error = Serializer.ReadVariableLength(stream).Value;

        return new(FrameType.ConnectionClose, null);
    }
}
