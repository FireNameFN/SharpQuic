using System;
using System.IO;
using System.Security.Cryptography;
using SharpQuic.Tls.Enums;
using SharpQuic.Tls.Extensions;

namespace SharpQuic.Tls.Messages;

public sealed class ServerHelloMessage : IMessage {
    public HandshakeType Type { get; } = HandshakeType.ServerHello;

    public KeyShareExtension.KeyShareEntry[] KeyShare { get; set; }

    public byte[] LegacySessionId { get; set; }

    public void Encode(Stream stream) {
        Serializer.WriteUInt16(stream, 0x0303);

        Span<byte> random = stackalloc byte[32];

        RandomNumberGenerator.Fill(random);

        stream.Write(random);

        Serializer.WriteByte(stream, (byte)LegacySessionId.Length);
        stream.Write(LegacySessionId);

        Serializer.WriteUInt16(stream, (ushort)CipherSuite.ChaCha20Poly1305Sha256);

        Serializer.WriteByte(stream, 0);

        byte[] extensions = GetExtensions();

        Serializer.WriteUInt16(stream, (ushort)extensions.Length);
        stream.Write(extensions);
    }

    public static ServerHelloMessage Decode(Stream stream) {
        stream.Position += 34;

        int length = Serializer.ReadByte(stream);
        stream.Position += length;

        stream.Position += 2;

        stream.Position++;

        ServerHelloMessage message = new();

        message.DecodeExtensions(stream);

        return message;
    }

    byte[] GetExtensions() {
        MemoryStream stream = new();

        SupportedVersionsExtension.EncodeServer(stream);
        KeyShareExtension.EncodeServer(stream, KeyShare[0]);

        return stream.ToArray();
    }

    void DecodeExtensions(Stream stream) {
        int length = Serializer.ReadUInt16(stream);

        long start = stream.Position;

        while(stream.Position - start < length) {
            ExtensionType type = (ExtensionType)Serializer.ReadUInt16(stream);

            int extensionLength = Serializer.ReadUInt16(stream);

            switch(type) {
                case ExtensionType.KeyShare:
                    KeyShare = [KeyShareExtension.DecodeServer(stream)];
                    
                    break;
                default:
                    stream.Position += extensionLength;
                    break;
            }
        }
    }
}
