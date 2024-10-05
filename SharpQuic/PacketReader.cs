using System.IO;

namespace SharpQuic;

public sealed class PacketReader {
    internal MemoryStream stream;

    public Frame Read() {
        FrameType type = (FrameType)Serializer.ReadVariableLength(stream).Value;

        return type switch {
            FrameType.Ack => ReadAck(),
            FrameType.Crypto => ReadCrypto(),
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
}
