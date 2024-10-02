using System;
using System.IO;
using Org.BouncyCastle.Crypto.Parameters;

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

        Span<byte> key = stackalloc byte[32];

        entry.KeyParameters.Encode(key);

        stream.Write(key);
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

        stream.Position += 2;

        Span<byte> key = stackalloc byte[32];

        stream.ReadExactly(key);

        return new(namedGroup, new(key));
    }

    public readonly record struct KeyShareEntry(NamedGroup NamedGroup, X25519PublicKeyParameters KeyParameters);
}
