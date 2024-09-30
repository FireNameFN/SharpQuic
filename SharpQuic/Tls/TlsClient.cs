using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace SharpQuic.Tls;

public sealed class TlsClient {
    public Stream InitialStream { get; set; }

    public Stream HandshakeStream { get; set; }

    public Stream OneRttStream { get; set; }

    readonly AsymmetricCipherKeyPair keyPair;

    public TlsClient() {
        X25519KeyPairGenerator generator = new();

        generator.Init(new(new(), 0));

        keyPair = generator.GenerateKeyPair();
    }

    public async Task HandshakeClientAsync() {
        await SendClientHelloAsync();
    }

    //public Task HandshakeServerAsync() {

    //}

    ValueTask SendClientHelloAsync() {
        MemoryStream stream = new();

        Serializer.WriteUInt16(stream, 0x0303);

        Span<byte> random = stackalloc byte[32];

        RandomNumberGenerator.Fill(random);

        stream.Write(random);

        Serializer.WriteByte(stream, 0);

        Serializer.WriteUInt16(stream, 1);
        Serializer.WriteUInt16(stream, 0x1303);

        Serializer.WriteByte(stream, 1);
        Serializer.WriteByte(stream, 0);

        byte[] extensions = GetExtensions();

        Serializer.WriteUInt16(stream, (ushort)extensions.Length);
        stream.Write(extensions);

        return SendHandshakeAsync(HandshakeType.ClientHello, stream.ToArray());
    }

    ValueTask SendServerHelloAsync() {
        MemoryStream stream = new();

        Serializer.WriteUInt16(stream, 0x0303);

        Span<byte> random = stackalloc byte[32];

        RandomNumberGenerator.Fill(random);

        stream.Write(random);



        return SendHandshakeAsync(HandshakeType.ServerHello, stream.ToArray());
    }

    byte[] GetExtensions() {
        MemoryStream stream = new();

        stream.Write(GetSupportedGroupsExtension());
        stream.Write(GetKeyShareExtension());

        return stream.ToArray();
    }

    byte[] GetSupportedGroupsExtension() {
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

    ValueTask SendHandshakeAsync(HandshakeType type, byte[] message) {
        MemoryStream stream = new();

        Serializer.WriteByte(stream, (byte)type);

        Serializer.WriteByte(stream, 0);
        Serializer.WriteUInt16(stream, (ushort)message.Length);

        stream.Write(message);

        if(type is HandshakeType.ClientHello or HandshakeType.ServerHello)
            return SendPlaintextAsync(InitialStream, ContentType.Handshake, stream.ToArray());
        else
            //return SendCiphertextAsync(HandshakeStream, ContentType.Handshake, stream.ToArray());
            return ValueTask.CompletedTask;
    }

    //ValueTask SendCiphertextAsync(Stream stream, ContentType type, byte[] fragment) {
        
    //}

    ValueTask SendPlaintextAsync(Stream stream, ContentType type, byte[] fragment) {
        MemoryStream memory = new();

        Serializer.WriteByte(memory, (byte)type);

        Serializer.WriteUInt16(memory, 0x0303);

        Serializer.WriteUInt16(memory, (ushort)fragment.Length);

        memory.Write(fragment);

        return stream.WriteAsync(memory.ToArray());
    }

    enum NamedGroup : ushort {
        SecP521r1 = 0x0019,
        X25519 = 0x001D
    }

    enum ExtensionType : ushort {
        SupportedGroups = 10,
        KeyShare = 51
    }

    enum HandshakeType : byte {
        ClientHello = 1,
        ServerHello = 2
    }

    enum ContentType : byte {
        Handshake = 22,
        ApplicationData = 23
    }
}
