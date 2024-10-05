using System.IO;
using SharpQuic.Tls.Enums;

namespace SharpQuic.Tls.Extensions;

public static class KeyShareExtension {
    public static void EncodeClient(Stream stream, KeyShareEntry[] entries) {
        Serializer.WriteUInt16(stream, (ushort)ExtensionType.KeyShare);

        Serializer.WriteUInt16(stream, (ushort)(entries.Length * 36 + 2));

        Serializer.WriteUInt16(stream, (ushort)(entries.Length * 36));

        foreach(KeyShareEntry entry in entries)
            EncodeEntry(stream, entry);
    }

    public static void EncodeServer(Stream stream, KeyShareEntry entry) {
        Serializer.WriteUInt16(stream, (ushort)ExtensionType.KeyShare);

        Serializer.WriteUInt16(stream, 36);

        EncodeEntry(stream, entry);
    }

    static void EncodeEntry(Stream stream, KeyShareEntry entry) {
        Serializer.WriteUInt16(stream, (ushort)entry.NamedGroup);

        Serializer.WriteUInt16(stream, 32);

        stream.Write(entry.Key);
    }

    public static KeyShareEntry[] DecodeClient(Stream stream) {
        int length = Serializer.ReadUInt16(stream) / 34;

        KeyShareEntry[] entries = new KeyShareEntry[length];

        for(int i = 0; i < length; i++)
            entries[i] = DecodeServer(stream);

        return entries;
    }

    public static KeyShareEntry DecodeServer(Stream stream) {
        NamedGroup namedGroup = (NamedGroup)Serializer.ReadUInt16(stream);

        int length = Serializer.ReadUInt16(stream);

        byte[] key = new byte[length];

        stream.ReadExactly(key);

        return new(namedGroup, key);
    }

    public readonly record struct KeyShareEntry(NamedGroup NamedGroup, byte[] Key);
}
