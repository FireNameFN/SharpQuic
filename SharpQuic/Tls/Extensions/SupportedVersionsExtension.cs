using System.IO;

namespace SharpQuic.Tls.Extensions;

public static class SupportedVersionsExtension {
    public static void EncodeClient(Stream stream) {
        Serializer.WriteUInt16(stream, (ushort)ExtensionType.SupportedVersions);

        Serializer.WriteUInt16(stream, 3);

        Serializer.WriteByte(stream, 2);
        Serializer.WriteUInt16(stream, 0x0304);
    }

    public static void EncodeServer(Stream stream) {
        Serializer.WriteUInt16(stream, (ushort)ExtensionType.SupportedVersions);

        Serializer.WriteUInt16(stream, 2);
        
        Serializer.WriteUInt16(stream, 0x0304);
    }

    public static void DecodeClient(Stream stream) {
        int length = Serializer.ReadByte(stream);
        stream.Position += length;
    }

    public static void DecodeServer(Stream stream) {
        stream.Position += 2;
    }
}
