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

    MemoryStream messages = new();

    byte[] hash;

    internal byte[] clientHandshakeSecret;

    internal byte[] serverHandshakeSecret;

    internal byte[] clientApplicationSecret;

    internal byte[] serverApplicationSecret;

    public TlsClient() {
        X25519KeyPairGenerator generator = new();

        generator.Init(new(new(), 1));

        keyPair = generator.GenerateKeyPair();
    }

    public void DeriveHandshakeSecrets() {
        hash = new byte[32];

        HKDF.Extract(HashAlgorithmName.SHA256, [], [], hash);

        HKDFExtensions.ExpandLabel(hash, "derived", hash);

        HKDF.Extract(HashAlgorithmName.SHA256, key, hash, hash);

        byte[] messagesArray = messages.ToArray();

        clientHandshakeSecret = new byte[32];

        HKDFExtensions.ExpandLabel(hash, "c hs traffic", messagesArray, clientHandshakeSecret);

        serverHandshakeSecret = new byte[32];

        HKDFExtensions.ExpandLabel(hash, "s hs traffic", messagesArray, serverHandshakeSecret);
    }

    public void DeriveApplicationSecrets() {
        HKDFExtensions.ExpandLabel(hash, "derived", hash);

        HKDF.Extract(HashAlgorithmName.SHA256, [], hash, hash);

        byte[] messagesArray = messages.ToArray();

        clientApplicationSecret = new byte[32];

        HKDFExtensions.ExpandLabel(hash, "c ap traffic", messagesArray, clientApplicationSecret);

        serverApplicationSecret = new byte[32];

        HKDFExtensions.ExpandLabel(hash, "s ap traffic", messagesArray, serverApplicationSecret);

        hash = null;
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

        byte[] extensions = GetClientExtensions();

        Serializer.WriteUInt16(stream, (ushort)extensions.Length);
        stream.Write(extensions);

        InitialPacketWriter.WriteCrypto(GetHandshake(HandshakeType.ClientHello, stream.ToArray()));
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

        byte[] extensions = GetServerExtensions();

        Serializer.WriteUInt16(stream, (ushort)extensions.Length);
        stream.Write(extensions);

        byte[] array = stream.ToArray();

        InitialPacketWriter.WriteCrypto(GetHandshake(HandshakeType.ServerHello, array));
    }

    public void SendServerHandshake() {
        MemoryStream stream = new();

        stream.Write(GetCertificate());

        stream.Write(GetFinished());

        HandshakePacketWriter.WriteCrypto(stream.ToArray());
    }

    byte[] GetCertificate() {
        MemoryStream stream = new();

        Serializer.WriteByte(stream, 0);

        Serializer.WriteByte(stream, 0);
        Serializer.WriteUInt16(stream, 0);

        return GetHandshake(HandshakeType.Certificate, stream.ToArray());
    }

    byte[] GetFinished() {
        Span<byte> key = stackalloc byte[32];

        HKDFExtensions.ExpandLabel(serverHandshakeSecret, "finished", key);

        Span<byte> data = stackalloc byte[32];

        HMACSHA256.HashData(key, messages.ToArray(), data);

        return GetHandshake(HandshakeType.Finished, data);
    }

    byte[] GetClientExtensions() {
        MemoryStream stream = new();

        stream.Write(GetSupportedVersionsExtension(EndpointType.Client));
        stream.Write(GetSupportedGroupsExtension());
        stream.Write(GetKeyShareExtension());

        return stream.ToArray();
    }

    byte[] GetServerExtensions() {
        MemoryStream stream = new();

        stream.Write(GetSupportedVersionsExtension(EndpointType.Server));
        stream.Write(GetKeyShareExtension());

        return stream.ToArray();
    }

    static byte[] GetSupportedVersionsExtension(EndpointType endpointType) {
        MemoryStream stream = new();

        Serializer.WriteUInt16(stream, (ushort)ExtensionType.SupportedVersions);

        if(endpointType == EndpointType.Client) {
            Serializer.WriteUInt16(stream, 3);
            Serializer.WriteByte(stream, sizeof(ushort));
            Serializer.WriteUInt16(stream, 0x0304);
        } else {
            Serializer.WriteUInt16(stream, 2);
            Serializer.WriteUInt16(stream, 0x0304);
        }

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

    byte[] GetHandshake(HandshakeType type, ReadOnlySpan<byte> message) {
        MemoryStream stream = new();

        Serializer.WriteByte(stream, (byte)type);

        Serializer.WriteByte(stream, 0);
        Serializer.WriteUInt16(stream, (ushort)message.Length);

        stream.Write(message);

        byte[] array = stream.ToArray();

        messages.Write(array);

        return array;
    }

    public void ReceiveHandshake(byte[] array) {
        MemoryStream stream = new(array);

        messages.Write(array);

        while(stream.Position < stream.Length) {
            HandshakeType type = (HandshakeType)Serializer.ReadByte(stream);

            stream.Position++;

            ushort length = Serializer.ReadUInt16(stream);

            switch(type) {
                case HandshakeType.ClientHello:
                    ReceiveClientHello(stream);
                    break;
                case HandshakeType.ServerHello:
                    ReceiveServerHello(stream);
                    break;
                default:
                    stream.Position += length;
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

            int extensionLength = Serializer.ReadUInt16(stream);

            switch(type) {
                case ExtensionType.SupportedGroups:
                    namedGroups = ReceiveSupportedGroupsExtension(stream);
                    break;
                case ExtensionType.KeyShare:
                    keys = ReceiveKeyShareExtension(stream);
                    break;
                default:
                    stream.Position += extensionLength;
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
        SupportedVersions = 43,
        KeyShare = 51
    }

    enum CipherSuite : ushort {
        ChaCha20Poly1305Sha256 = 0x1303
    }

    enum HandshakeType : byte {
        ClientHello = 1,
        ServerHello = 2,
        Certificate = 11,
        CertificateVerify = 15,
        Finished = 20
    }
}
