using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using SharpQuic.Tls.Extensions;
using SharpQuic.Tls.Messages;

namespace SharpQuic.Tls;

public sealed class TlsClient {
    public IFragmentWriter InitialFragmentWriter { get; set; }

    public IFragmentWriter HandshakeFragmentWriter { get; set; }

    X509Certificate[] certificateChain;

    AsymmetricCipherKeyPair keyPair;

    internal byte[] key = new byte[32];

    byte[] legacySessionId;

    MemoryStream messages = new();

    byte[] hash;

    internal byte[] clientHandshakeSecret;

    internal byte[] serverHandshakeSecret;

    internal byte[] clientApplicationSecret;

    internal byte[] serverApplicationSecret;

    public TlsClient(X509Certificate[] certificateChain = null) {
        this.certificateChain = certificateChain ?? [];

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

        keyPair = null;
        key = null;
    }

    public void DeriveApplicationSecrets() {
        HKDFExtensions.ExpandLabel(hash, "derived", hash);

        HKDF.Extract(HashAlgorithmName.SHA256, [], hash, hash);

        byte[] messagesArray = messages.ToArray();

        clientApplicationSecret = new byte[32];

        HKDFExtensions.ExpandLabel(hash, "c ap traffic", messagesArray, clientApplicationSecret);

        serverApplicationSecret = new byte[32];

        HKDFExtensions.ExpandLabel(hash, "s ap traffic", messagesArray, serverApplicationSecret);

        messages = null;
        hash = null;
    }

    public void SendClientHello() {
        ClientHelloMessage message = new() {
            KeyShare = [new(NamedGroup.X25519, (X25519PublicKeyParameters)keyPair.Public)]
        };

        InitialFragmentWriter.WriteFragment(GetHandshake(message));
    }

    public void SendServerHello() {
        ServerHelloMessage message = new() {
            KeyShare = [new(NamedGroup.X25519, (X25519PublicKeyParameters)keyPair.Public)],
            LegacySessionId = legacySessionId
        };

        InitialFragmentWriter.WriteFragment(GetHandshake(message));
    }

    public void SendServerHandshake() {
        MemoryStream stream = new();

        CertificateMessage certificateMessage = new() {
            CertificateChain = [..certificateChain]
        };

        stream.Write(GetHandshake(certificateMessage));

        FinishedMessage finishedMessage = new() {
            Messages = messages.ToArray(),
            ServerHandshakeSecret = serverHandshakeSecret
        };

        stream.Write(GetHandshake(finishedMessage));

        HandshakeFragmentWriter.WriteFragment(stream.ToArray());
    }

    byte[] GetHandshake(IMessage message) {
        MemoryStream messageStream = new();

        message.Encode(messageStream);

        byte[] encodedMessage = messageStream.ToArray();

        MemoryStream stream = new();

        Serializer.WriteByte(stream, (byte)message.Type);

        Serializer.WriteByte(stream, 0);
        Serializer.WriteUInt16(stream, (ushort)encodedMessage.Length);

        stream.Write(encodedMessage);

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
                    ReceiveClientHello(ClientHelloMessage.Decode(stream));
                    break;
                case HandshakeType.ServerHello:
                    ReceiveServerHello(ServerHelloMessage.Decode(stream));
                    break;
                default:
                    stream.Position += length;
                    break;
            }
        }
    }

    void ReceiveClientHello(ClientHelloMessage message) {
        DeriveKey(message.KeyShare);

        legacySessionId = message.LegacySessionId;
    }

    void ReceiveServerHello(ServerHelloMessage message) {
        DeriveKey(message.KeyShare);
    }

    void DeriveKey(KeyShareExtension.KeyShareEntry[] keyShare) {
        X25519PublicKeyParameters key = keyShare.First(key => key.NamedGroup == NamedGroup.X25519).KeyParameters;

        X25519Agreement agreement = new();

        agreement.Init(keyPair.Private);

        agreement.CalculateAgreement(key, this.key);
    }
}
