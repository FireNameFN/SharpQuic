using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Agreement.Kdf;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using SharpQuic.Tls.Enums;
using SharpQuic.Tls.Extensions;
using SharpQuic.Tls.Messages;

namespace SharpQuic.Tls;

public sealed class TlsClient {
    public IFragmentWriter InitialFragmentWriter { get; set; }

    public IFragmentWriter HandshakeFragmentWriter { get; set; }

    public TlsState State { get; private set; }

    readonly QuicTransportParameters parameters;

    string[] protocols;

    X509Certificate2[] certificateChain;

    X509Certificate2[] remoteCertificateChain;

    AsymmetricCipherKeyPair keyPair;
    AsymmetricCipherKeyPair keyPair1;

    internal byte[] key = new byte[32];

    byte[] legacySessionId;

    MemoryStream messages = new();

    byte[] hash;

    internal byte[] clientHandshakeSecret;

    internal byte[] serverHandshakeSecret;

    internal byte[] clientApplicationSecret;

    internal byte[] serverApplicationSecret;

    public TlsClient(QuicTransportParameters parameters, string[] protocols, X509Certificate2[] certificateChain = null) {
        this.parameters = parameters;
        this.protocols = protocols;
        this.certificateChain = certificateChain ?? [];

        X25519KeyPairGenerator generator = new();

        generator.Init(new(new(), 1));

        keyPair = generator.GenerateKeyPair();

        ECKeyPairGenerator generator1 = new();

        X9ECParameters parameters1 = ECNamedCurveTable.GetByName("secp256r1");

        generator1.Init(new ECKeyGenerationParameters(new ECDomainParameters(parameters1), new()));

        keyPair1 = generator1.GenerateKeyPair();
    }

    public void DeriveHandshakeSecrets() {
        hash = new byte[32];

        HKDF.Extract(HashAlgorithmName.SHA256, hash, [], hash);

        HKDFExtensions.ExpandLabel(HashAlgorithmName.SHA256, hash, "derived", SHA256.HashData([]), hash);

        HKDF.Extract(HashAlgorithmName.SHA256, key, hash, hash);

        Span<byte> messagesHash = stackalloc byte[32];

        SHA256.HashData(messages.ToArray(), messagesHash);

        clientHandshakeSecret = new byte[32];

        HKDFExtensions.ExpandLabel(HashAlgorithmName.SHA256, hash, "c hs traffic", messagesHash, clientHandshakeSecret);

        serverHandshakeSecret = new byte[32];

        HKDFExtensions.ExpandLabel(HashAlgorithmName.SHA256, hash, "s hs traffic", messagesHash, serverHandshakeSecret);

        keyPair = null;
        key = null;
    }

    public void DeriveApplicationSecrets() {
        HKDFExtensions.ExpandLabel(hash, "derived", hash);

        HKDF.Extract(HashAlgorithmName.SHA256, [], hash, hash);

        Span<byte> messagesHash = stackalloc byte[32];

        SHA256.HashData(messages.ToArray(), messagesHash);

        clientApplicationSecret = new byte[32];

        HKDFExtensions.ExpandLabel(HashAlgorithmName.SHA256, hash, "c ap traffic", messagesHash, clientApplicationSecret);

        serverApplicationSecret = new byte[32];

        HKDFExtensions.ExpandLabel(HashAlgorithmName.SHA256, hash, "s ap traffic", messagesHash, serverApplicationSecret);

        messages = null;
        hash = null;
    }

    public void SendClientHello() {
        byte[] key = new byte[32];

        ((X25519PublicKeyParameters)keyPair.Public).Encode(key);

        byte[] k = new byte[32];

        byte[] k1 = new byte[32];

        ((ECPublicKeyParameters)keyPair1.Public).Q.XCoord.GetEncoded().AsSpan().CopyTo(k);

        ((ECPublicKeyParameters)keyPair1.Public).Q.XCoord.GetEncoded().AsSpan().CopyTo(k1);

        byte[] key1 = [4, ..k, ..k1];

        ClientHelloMessage message = new() {
            KeyShare = [new(NamedGroup.X25519, key), new(NamedGroup.SecP256r1, key1)],
            Protocols = protocols,
            Parameters = parameters
        };

        InitialFragmentWriter.WriteFragment(GetHandshake(message));

        State = TlsState.WaitServerHello;
    }

    public void SendServerHello() {
        byte[] key = new byte[32];

        ((X25519PublicKeyParameters)keyPair.Public).Encode(key);

        ServerHelloMessage message = new() {
            KeyShare = [new(NamedGroup.X25519, key)],
            LegacySessionId = legacySessionId
        };

        InitialFragmentWriter.WriteFragment(GetHandshake(message));
    }

    public void SendServerHandshake() {
        MemoryStream stream = new();

        EncryptedExtensionsMessage encryptedExtensionsMessage = new() {
            Protocol = protocols[0]
        };

        stream.Write(GetHandshake(encryptedExtensionsMessage));

        CertificateMessage certificateMessage = new() {
            CertificateChain = certificateChain
        };

        stream.Write(GetHandshake(certificateMessage));

        if(certificateChain.Length > 0) {
            CertificateVerifyMessage certificateVerifyMessage = CertificateVerifyMessage.Create(EndpointType.Server, messages.ToArray(), certificateChain[0]);

            stream.Write(GetHandshake(certificateVerifyMessage));
        }

        FinishedMessage finishedMessage = new() {
            Messages = messages.ToArray(),
            ServerHandshakeSecret = serverHandshakeSecret
        };

        stream.Write(GetHandshake(finishedMessage));

        HandshakeFragmentWriter.WriteFragment(stream.ToArray());
    }

    public void SendClientFinished() {
        FinishedMessage finishedMessage = new() {
            Messages = messages.ToArray(),
            ServerHandshakeSecret = serverHandshakeSecret
        };

        HandshakeFragmentWriter.WriteFragment(GetHandshake(finishedMessage));
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

        if(message is ClientHelloMessage)
            messages.SetLength(0);

        messages.Write(array);

        return array;
    }

    public static (HandshakeType Type, int Length) ReadHandshakeHeader(byte[] data) {
        MemoryStream stream = new(data);

        HandshakeType type = (HandshakeType)Serializer.ReadByte(stream);

        stream.Position++;

        ushort length = Serializer.ReadUInt16(stream);

        return (type, length);
    }

    public void ReceiveHandshake(HandshakeType type, byte[] data) {
        /*await Task.Yield();

        HandshakeType type = (HandshakeType)Serializer.ReadByte(stream);

        //stream.Position++;

        stream.ReadByte();

        ushort length = Serializer.ReadUInt16(stream);

        byte[] message = new byte[length];

        await stream.ReadExactlyAsync(message);*/

        //stream.Position -= length;

        MemoryStream messageStream = new(data);

        switch(type) {
            case HandshakeType.ClientHello:
                ReceiveClientHello(ClientHelloMessage.Decode(messageStream));
                break;
            case HandshakeType.ServerHello:
                ReceiveServerHello(ServerHelloMessage.Decode(messageStream));
                break;
            case HandshakeType.EncryptedExtensions:
                ReceiveEncryptedExtensions(EncryptedExtensionsMessage.Decode(messageStream));
                break;
            case HandshakeType.Certificate:
                ReceiveCertificate(CertificateMessage.Decode(messageStream));
                break;
            case HandshakeType.CertificateVerify:
                ReceiveCertificateVerify(CertificateVerifyMessage.Decode(messageStream));
                break;
            case HandshakeType.Finished:
                ReceiveFinished(FinishedMessage.Decode(messageStream));
                break;
            default:
                //messageStream.Position += length;
                throw new NotImplementedException();
                //break;
        }

        Serializer.WriteByte(messages, (byte)type);
        Serializer.WriteByte(messages, 0);
        Serializer.WriteUInt16(messages, (ushort)data.Length);

        messages.Write(data);
    }

    void ReceiveClientHello(ClientHelloMessage message) {
        DeriveKey(message.KeyShare);

        legacySessionId = message.LegacySessionId;
    }

    void ReceiveServerHello(ServerHelloMessage message) {
        DeriveKey(message.KeyShare);

        State = TlsState.WaitEncryptedExtensions;
    }

    void ReceiveEncryptedExtensions(EncryptedExtensionsMessage message) {
        State = TlsState.WaitCertificate;
    }

    void ReceiveCertificate(CertificateMessage message) {
        remoteCertificateChain = message.CertificateChain;

        State = TlsState.WaitCertificateVerify;
    }

    void ReceiveCertificateVerify(CertificateVerifyMessage message) {
        if(!CertificateVerifyMessage.Verify(EndpointType.Server, remoteCertificateChain[0], message.Signature, messages.ToArray()))
            throw new QuicException();
    }

    void ReceiveFinished(FinishedMessage message) {
        State = TlsState.Connected;
    }

    void DeriveKey(KeyShareExtension.KeyShareEntry[] keyShare) {
        X25519PublicKeyParameters key = new(keyShare.First(key => key.NamedGroup == NamedGroup.X25519).Key);

        X25519Agreement agreement = new();

        agreement.Init(keyPair.Private);

        agreement.CalculateAgreement(key, this.key);
    }

    public enum TlsState {
        Start,
        WaitServerHello,
        WaitClientHello,
        WaitEncryptedExtensions,
        WaitCertificate,
        WaitCertificateVerify,
        WaitFinished,
        Connected
    }
}
