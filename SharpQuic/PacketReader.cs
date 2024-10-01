using System.IO;

namespace SharpQuic;

public sealed class PacketReader {
    internal MemoryStream stream;

    public Frame Read() {
        FrameType type = (FrameType)Serializer.ReadVariableLength(stream);

        return type switch {
            FrameType.Crypto => ReadCrypto(),
            _ => throw new QuicException()
        };
    }

    Frame ReadCrypto() {
        Serializer.ReadVariableLength(stream);

        ulong length = Serializer.ReadVariableLength(stream);

        byte[] data = new byte[length];

        stream.ReadExactly(data);

        return new(FrameType.Crypto, data);
    }
}
