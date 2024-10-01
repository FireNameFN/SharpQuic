using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace SharpQuic.Tls;

public sealed class TlsClient {
    public PacketWriter InitialPacketWriter { get; set; }

    public PacketWriter HandshakePacketWriter { get; set; }

    readonly AsymmetricCipherKeyPair keyPair;

    internal readonly byte[] key = new byte[32];

    uint legacySessionId;

    byte[] clientHello;

    byte[] serverHello;

    byte[] serverFinished;

    internal byte[] clientHandshakeSecret;

    internal byte[] serverHandshakeSecret;

    public TlsClient() {
        X25519KeyPairGenerator generator = new();

        generator.Init(new(new(), 1));

        keyPair = generator.GenerateKeyPair();
    }

    public void DeriveSecrets() {
        Span<byte> hash = stackalloc byte[32];

        HKDF.Extract(HashAlgorithmName.SHA256, [], [], hash);

        HKDFExtensions.ExpandLabel(hash, "derived", hash);

        HKDF.Extract(HashAlgorithmName.SHA256, key, hash, hash);

        clientHandshakeSecret = new byte[32];

        HKDFExtensions.ExpandLabel(hash, "c hs traffic", [..clientHello, ..serverHello], clientHandshakeSecret);

        serverHandshakeSecret = new byte[32];

        HKDFExtensions.ExpandLabel(hash, "s hs traffic", [..clientHello, ..serverHello], serverHandshakeSecret);
    }

    public void SendClientHello() {
        MemoryStream stream = new();

        Serializer.WriteUInt16(stream, 0x0303);

        Span<byte> random = stackalloc byte[32];

        RandomNumberGenerator.Fill(random);

        stream.Write(random);

        Serializer.WriteByte(stream, 0);

        Serializer.WriteUInt16(stream, 2);
        Serializer.WriteUInt16(stream, (ushort)CipherSuite.ChaCha20Poly1305Sha256);

        Serializer.WriteByte(stream, 1);
        Serializer.WriteByte(stream, 0);

        byte[] extensions = GetExtensions();

        Serializer.WriteUInt16(stream, (ushort)extensions.Length);
        stream.Write(extensions);

        SendHandshake(HandshakeType.ClientHello, stream.ToArray());
    }

    public void SendServerHello() {
        MemoryStream stream = new();

        Serializer.WriteUInt16(stream, 0x0303);

        Span<byte> random = stackalloc byte[32];

        RandomNumberGenerator.Fill(random);

        stream.Write(random);

        int legacySessionIdLength = Serializer.GetLength(legacySessionId);

        Serializer.WriteByte(stream, (byte)legacySessionIdLength);
        Serializer.WriteWithLength(stream, legacySessionId, legacySessionIdLength);

        Serializer.WriteUInt16(stream, (ushort)CipherSuite.ChaCha20Poly1305Sha256);

        Serializer.WriteByte(stream, 0);

        byte[] extensions = GetKeyShareExtension();

        Serializer.WriteUInt16(stream, (ushort)extensions.Length);
        stream.Write(extensions);

        SendHandshake(HandshakeType.ServerHello, stream.ToArray());
    }

    byte[] GetExtensions() {
        MemoryStream stream = new();

        stream.Write(GetSupportedGroupsExtension());
        stream.Write(GetKeyShareExtension());

        return stream.ToArray();
    }

    static byte[] GetSupportedGroupsExtension() {
        MemoryStream stream = new();

        Serializer.WriteUInt16(stream, (ushort)ExtensionType.SupportedGroups);

        Serializer.WriteUInt16(stream, 4);

        Serializer.WriteUInt16(stream, 2);
        Serializer.WriteUInt16(stream, (ushort)NamedGroup.X25519);

        return stream.ToArray();
    }

    byte[] GetKeyShareExtension() {
        MemoryStream stream = new();

        Serializer.WriteUInt16(stream, (ushort)ExtensionType.KeyShare);

        byte[] key = ((X25519PublicKeyParameters)keyPair.Public).GetEncoded();

        Serializer.WriteUInt16(stream, (ushort)(key.Length + 6));

        Serializer.WriteUInt16(stream, (ushort)(key.Length + 4));
        Serializer.WriteUInt16(stream, (ushort)NamedGroup.X25519);
        Serializer.WriteUInt16(stream, (ushort)key.Length);
        stream.Write(key);

        return stream.ToArray();
    }

    void SendHandshake(HandshakeType type, byte[] message) {
        MemoryStream stream = new();

        Serializer.WriteByte(stream, (byte)type);

        Serializer.WriteByte(stream, 0);
        Serializer.WriteUInt16(stream, (ushort)message.Length);

        stream.Write(message);

        if(type is HandshakeType.ClientHello or HandshakeType.ServerHello) {
            byte[] array = stream.ToArray();

            InitialPacketWriter.WriteCrypto(array);

            if(type == HandshakeType.ClientHello)
                clientHello = array;
            else
                serverHello = array;
        } else
            HandshakePacketWriter.WriteCrypto(stream.ToArray());
    }

    public void ReceiveHandshake(byte[] array) {
        MemoryStream stream = new(array);

        while(stream.Position < stream.Length) {
            HandshakeType type = (HandshakeType)Serializer.ReadByte(stream);

            stream.Position += 3;

            switch(type) {
                case HandshakeType.ClientHello:
                    ReceiveClientHello(stream);

                    clientHello = array;

                    break;
                case HandshakeType.ServerHello:
                    ReceiveServerHello(stream);

                    serverHello = array;

                    break;
            }
        }
    }

    void ReceiveClientHello(MemoryStream stream) {
        stream.Position += 34;

        int length = Serializer.ReadByte(stream);
        legacySessionId = Serializer.ReadWithLength(stream, length);

        length = Serializer.ReadUInt16(stream);
        stream.Position += length;

        stream.Position += 2;

        ReceiveExtensions(stream);
    }

    void ReceiveServerHello(MemoryStream stream) {
        stream.Position += 34;

        int length = Serializer.ReadByte(stream);
        stream.Position += length;

        stream.Position += 2;

        stream.Position++;

        ReceiveExtensions(stream);
    }

    void ReceiveExtensions(Stream stream) {
        int length = Serializer.ReadUInt16(stream);

        long start = stream.Position;

        List<NamedGroup> namedGroups;
        List<NamedGroupKey> keys = null;

        while(stream.Position - start < length) {
            ExtensionType type = (ExtensionType)Serializer.ReadUInt16(stream);

            stream.Position += 2;

            switch(type) {
                case ExtensionType.SupportedGroups:
                    namedGroups = ReceiveSupportedGroupsExtension(stream);
                    break;
                case ExtensionType.KeyShare:
                    keys = ReceiveKeyShareExtension(stream);
                    break;
            }
        }

        byte[] key = keys.First(key => key.NamedGroup == NamedGroup.X25519).Key;

        X25519Agreement agreement = new();

        agreement.Init(keyPair.Private);

        agreement.CalculateAgreement(new X25519PublicKeyParameters(key), this.key);
    }

    static List<NamedGroup> ReceiveSupportedGroupsExtension(Stream stream) {
        int length = Serializer.ReadUInt16(stream);

        List<NamedGroup> list = new(length / 2);

        long start = stream.Position;

        while(stream.Position - start < length)
            list.Add((NamedGroup)Serializer.ReadUInt16(stream));

        return list;
    }

    static List<NamedGroupKey> ReceiveKeyShareExtension(Stream stream) {
        List<NamedGroupKey> list = [];

        int length = Serializer.ReadUInt16(stream);

        long start = stream.Position;

        while(stream.Position - start < length) {
            NamedGroup namedGroup = (NamedGroup)Serializer.ReadUInt16(stream);

            int keyLength = Serializer.ReadUInt16(stream);

            byte[] key = new byte[keyLength];

            stream.ReadExactly(key);

            list.Add(new(namedGroup, key));
        }

        return list;
    }

    readonly record struct NamedGroupKey(NamedGroup NamedGroup, byte[] Key);

    enum NamedGroup : ushort {
        SecP521r1 = 0x0019,
        X25519 = 0x001D
    }

    enum ExtensionType : ushort {
        SupportedGroups = 10,
        KeyShare = 51
    }

    enum CipherSuite : ushort {
        ChaCha20Poly1305Sha256 = 0x1303
    }

    enum HandshakeType : byte {
        ClientHello = 1,
        ServerHello = 2
    }
}
