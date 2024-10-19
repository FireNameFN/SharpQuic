using System;
using System.IO;
using System.Security.Cryptography;
using SharpQuic.Tls.Enums;
using SharpQuic.Tls.Extensions;

namespace SharpQuic.Tls.Messages;

public sealed class ClientHelloMessage : IMessage {
    public HandshakeType Type { get; } = HandshakeType.ClientHello;

    public CipherSuite[] CipherSuites { get; set; }

    public KeyShareExtension.KeyShareEntry[] KeyShare { get; set; }

    public string[] Protocols { get; set; }

    public byte[] LegacySessionId { get; set; }

    public QuicTransportParameters Parameters { get; set; }

    public void Encode(Stream stream) {
        Serializer.WriteUInt16(stream, 0x0303);

        Span<byte> random = stackalloc byte[32];

        RandomNumberGenerator.Fill(random);

        stream.Write(random);

        Serializer.WriteByte(stream, 0);

        Serializer.WriteUInt16(stream, (ushort)(CipherSuites.Length * 2));

        foreach(CipherSuite cipherSuite in CipherSuites)
            Serializer.WriteUInt16(stream, (ushort)cipherSuite);

        Serializer.WriteByte(stream, 1);
        Serializer.WriteByte(stream, 0);

        byte[] extensions = GetExtensions();

        Serializer.WriteUInt16(stream, (ushort)extensions.Length);
        stream.Write(extensions);
    }

    public static ClientHelloMessage Decode(Stream stream) {
        ClientHelloMessage message = new();

        stream.Position += 34;

        int length = Serializer.ReadByte(stream);

        message.LegacySessionId = new byte[length];

        stream.Read(message.LegacySessionId);

        length = Serializer.ReadUInt16(stream) / 2;

        message.CipherSuites = new CipherSuite[length];

        for(int i = 0; i < length; i++)
            message.CipherSuites[i] = (CipherSuite)Serializer.ReadUInt16(stream);

        stream.Position += 2;

        message.DecodeExtensions(stream);

        return message;
    }

    byte[] GetExtensions() {
        MemoryStream stream = new();

        SupportedVersionsExtension.EncodeClient(stream);
        SignatureAlgorithmsExtension.Encode(stream);
        SupportedGroupsExtension.Encode(stream);
        KeyShareExtension.EncodeClient(stream, KeyShare);
        AlpnExtension.Encode(stream, Protocols);
        QuicTransportParametersExtension.Encode(stream, Parameters);

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
                    KeyShare = KeyShareExtension.DecodeClient(stream);
                    
                    break;
                default:
                    stream.Position += extensionLength;
                    break;
            }
        }
    }
}
