using System.IO;

namespace SharpQuic.Tls.Extensions;

public static class SupportedGroupsExtension {
    public static void Encode(Stream stream) {
        Serializer.WriteUInt16(stream, (ushort)ExtensionType.SupportedGroups);

        Serializer.WriteUInt16(stream, 4);

        Serializer.WriteUInt16(stream, 2);
        Serializer.WriteUInt16(stream, (ushort)NamedGroup.X25519);
    }

    public static void Decode(Stream stream) {
        int length = Serializer.ReadUInt16(stream);
        stream.Position += length;
    }
}
