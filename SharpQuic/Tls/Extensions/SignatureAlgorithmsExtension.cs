using System.IO;

namespace SharpQuic.Tls.Extensions;

public static class SignatureAlgorithmsExtension {
    public static void Encode(Stream stream) {
        Serializer.WriteUInt16(stream, (ushort)ExtensionType.SignatureAlgorithms);

        Serializer.WriteUInt16(stream, 4);

        Serializer.WriteUInt16(stream, 2);
        Serializer.WriteUInt16(stream, (ushort)SignatureScheme.RSAPkcs1SHA256);
    }

    public static void Decode(Stream stream) {
        int length = Serializer.ReadUInt16(stream);
        stream.Position += length;
    }
}
