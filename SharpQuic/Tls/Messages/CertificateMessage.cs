using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using SharpQuic.Tls.Enums;

namespace SharpQuic.Tls.Messages;

public sealed class CertificateMessage : IMessage {
    public HandshakeType Type { get; } = HandshakeType.Certificate;

    public X509Certificate2[] CertificateChain { get; set; }

    public void Encode(Stream stream) {
        Serializer.WriteByte(stream, 0);

        MemoryStream certificateStream = new();

        foreach(X509Certificate2 certificate in CertificateChain) {
            byte[] data = certificate.GetRawCertData();

            Serializer.WriteByte(certificateStream, 0);
            Serializer.WriteUInt16(certificateStream, (ushort)data.Length);

            certificateStream.Write(data);

            Serializer.WriteUInt16(certificateStream, 0);
        }

        certificateStream.Position = 0;

        Serializer.WriteByte(stream, 0);
        Serializer.WriteUInt16(stream, (ushort)certificateStream.Length);
        certificateStream.CopyTo(stream);
    }

    public static CertificateMessage Decode(Stream stream) {
        int length = Serializer.ReadByte(stream);
        stream.Position += length;

        stream.Position++;
        length = Serializer.ReadUInt16(stream);

        List<X509Certificate2> certificateChain = [];

        long start = stream.Position;

        while(stream.Position - start < length) {
            stream.Position++;
            int length2 = Serializer.ReadUInt16(stream);

            byte[] data = new byte[length2];
            stream.ReadExactly(data);

            certificateChain.Add(new(data));

            length2 = Serializer.ReadUInt16(stream);
            stream.Position += length2;
        }

        return new CertificateMessage() {
            CertificateChain = [..certificateChain]
        };
    }
}
