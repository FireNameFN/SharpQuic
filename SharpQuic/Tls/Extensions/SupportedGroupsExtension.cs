using System.IO;
using SharpQuic.Tls.Enums;

namespace SharpQuic.Tls.Extensions;

public static class SupportedGroupsExtension {
    public static void Encode(Stream stream) {
        Serializer.WriteUInt16(stream, (ushort)ExtensionType.SupportedGroups);

        Serializer.WriteUInt16(stream, 6);

        Serializer.WriteUInt16(stream, 4);
        Serializer.WriteUInt16(stream, (ushort)NamedGroup.SecP256r1);
        Serializer.WriteUInt16(stream, (ushort)NamedGroup.X25519);
    }

    public static void Decode(Stream stream) {
        int length = Serializer.ReadUInt16(stream);
        stream.Position += length;
    }
}
