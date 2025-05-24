using System.IO;
using SharpQuic.Tls.Enums;
using SharpQuic.Tls.Extensions;

namespace SharpQuic.Tls.Messages;

public sealed class CertificateRequestMessage : IMessage {
    public HandshakeType Type { get; } = HandshakeType.CertificateRequest;

    public void Encode(Stream stream) {
        Serializer.WriteByte(stream, 0);

        MemoryStream extensionsStream = new();

        SignatureAlgorithmsExtension.Encode(extensionsStream);

        Serializer.WriteUInt16(stream, (ushort)extensionsStream.Length);

        extensionsStream.Position = 0;
        extensionsStream.CopyTo(stream);
    }

    public static CertificateRequestMessage Decode(Stream stream) {
        byte contextLength = Serializer.ReadByte(stream);

        stream.Position += contextLength;

        ushort extensionsLength = Serializer.ReadUInt16(stream);

        stream.Position += extensionsLength;

        return new();
    }
}
