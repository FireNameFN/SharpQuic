using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
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

    public CipherSuite CipherSuite { get; private set; }

    readonly QuicTransportParameters parameters;

    string[] protocols;

    X509Certificate2[] certificateChain;

    X509Certificate2[] remoteCertificateChain;

    AsymmetricCipherKeyPair keyPair;
    AsymmetricCipherKeyPair keyPair1;

    internal byte[] key = new byte[32];

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
        HashAlgorithmName name = HashUtils.GetName(CipherSuite);

        hash = new byte[HashUtils.GetLength(name)];

        HKDF.Extract(name, hash, hash, hash);

        IncrementalHash incrementalHash = IncrementalHash.CreateHash(name);

        HKDFExtensions.ExpandLabel(name, hash, "derived", incrementalHash.GetCurrentHash(), hash);

        HKDF.Extract(name, key, hash, hash);

        Span<byte> messagesHash = stackalloc byte[hash.Length];

        GetMessagesHash(name, messagesHash);

        clientHandshakeSecret = new byte[hash.Length];

        HKDFExtensions.ExpandLabel(name, hash, "c hs traffic", messagesHash, clientHandshakeSecret);

        serverHandshakeSecret = new byte[hash.Length];

        HKDFExtensions.ExpandLabel(name, hash, "s hs traffic", messagesHash, serverHandshakeSecret);

        keyPair = null;
        key = null;
    }

    public void DeriveApplicationSecrets() {
        HashAlgorithmName name = HashUtils.GetName(CipherSuite);

        IncrementalHash incrementalHash = IncrementalHash.CreateHash(name);

        HKDFExtensions.ExpandLabel(name, hash, "derived", incrementalHash.GetCurrentHash(), hash);

        Span<byte> messagesHash = stackalloc byte[hash.Length];

        HKDF.Extract(name, messagesHash, hash, hash);

        GetMessagesHash(name, messagesHash);

        clientApplicationSecret = new byte[hash.Length];

        HKDFExtensions.ExpandLabel(name, hash, "c ap traffic", messagesHash, clientApplicationSecret);

        serverApplicationSecret = new byte[hash.Length];

        HKDFExtensions.ExpandLabel(name, hash, "s ap traffic", messagesHash, serverApplicationSecret);

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
            CipherSuites = [CipherSuite.Aes256GcmSHA384],
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
            CipherSuite = CipherSuite,
            KeyShare = [new(NamedGroup.X25519, key)]
        };

        InitialFragmentWriter.WriteFragment(GetHandshake(message));
    }

    public void SendServerHandshake() {
        MemoryStream stream = new();

        EncryptedExtensionsMessage encryptedExtensionsMessage = new() {
            Protocol = protocols[0],
            Parameters = parameters
        };

        stream.Write(GetHandshake(encryptedExtensionsMessage));

        CertificateMessage certificateMessage = new() {
            CertificateChain = certificateChain
        };

        stream.Write(GetHandshake(certificateMessage));

        HashAlgorithmName name = HashUtils.GetName(CipherSuite);

        if(certificateChain.Length > 0) {
            CertificateVerifyMessage certificateVerifyMessage = CertificateVerifyMessage.Create(EndpointType.Server, GetMessagesHash(name), certificateChain[0]);

            stream.Write(GetHandshake(certificateVerifyMessage));
        }

        FinishedMessage finishedMessage = FinishedMessage.Create(name, GetMessagesHash(name), serverHandshakeSecret);

        stream.Write(GetHandshake(finishedMessage));

        HandshakeFragmentWriter.WriteFragment(stream.ToArray());

        State = TlsState.WaitClientFinished;
    }

    public void SendClientFinished() {
        HashAlgorithmName name = HashUtils.GetName(CipherSuite);

        FinishedMessage finishedMessage = FinishedMessage.Create(name, GetMessagesHash(name), clientHandshakeSecret);

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

        if(State != TlsState.Connected || message is not FinishedMessage)
            messages.Write(array);

        return array;
    }

    public bool TryReceiveHandshake(Stream stream) {
        if(stream.Length - stream.Position < 4)
            return false;

        long position = stream.Position;

        HandshakeType type = (HandshakeType)Serializer.ReadByte(stream);

        stream.Position++;

        ushort length = Serializer.ReadUInt16(stream);

        if(stream.Length - stream.Position < length)
            return false;

        TlsState state = State;

        switch(type) {
            case HandshakeType.ClientHello:
                ReceiveClientHello(ClientHelloMessage.Decode(stream));
                Console.WriteLine($"Received ClientHello");
                break;
            case HandshakeType.ServerHello:
                ReceiveServerHello(ServerHelloMessage.Decode(stream));
                Console.WriteLine($"Received ServerHello");
                break;
            case HandshakeType.NewSessionTicket:
                Console.WriteLine($"Received NewSessionTicket");
                break;
            case HandshakeType.EncryptedExtensions:
                ReceiveEncryptedExtensions(EncryptedExtensionsMessage.Decode(stream));
                Console.WriteLine($"Received EncryptedExtensions");
                break;
            case HandshakeType.Certificate:
                ReceiveCertificate(CertificateMessage.Decode(stream));
                Console.WriteLine($"Received Certificate");
                break;
            case HandshakeType.CertificateVerify:
                ReceiveCertificateVerify(CertificateVerifyMessage.Decode(stream));
                Console.WriteLine($"Received CertificateVerify");
                break;
            case HandshakeType.Finished:
                ReceiveFinished(FinishedMessage.Decode(HashUtils.GetName(CipherSuite), stream));
                Console.WriteLine($"Received Finished");
                break;
            default:
                //messageStream.Position += length;
                throw new NotImplementedException();
                //break;
        }

        if(state == TlsState.WaitClientFinished)
            return true;

        int handshakeLength = (int)(stream.Position - position);

        stream.Position = position;

        Span<byte> message = stackalloc byte[handshakeLength];

        stream.ReadExactly(message);

        messages.Write(message);

        return true;
    }

    void ReceiveClientHello(ClientHelloMessage message) {
        if(State != TlsState.Start)
            throw new QuicException();

        if(message.CipherSuites.Contains(CipherSuite.ChaCha20Poly1305Sha256))
            CipherSuite = CipherSuite.ChaCha20Poly1305Sha256;
        else if(message.CipherSuites.Contains(CipherSuite.Aes256GcmSHA384))
            CipherSuite = CipherSuite.Aes256GcmSHA384;
        else
            CipherSuite = CipherSuite.Aes128GcmSHA256;

        DeriveKey(message.KeyShare);

        if(message.LegacySessionId.Length > 0)
            throw new QuicException();

        State = TlsState.WaitClientFinished;
    }

    void ReceiveServerHello(ServerHelloMessage message) {
        if(State != TlsState.WaitServerHello)
            throw new QuicException();

        CipherSuite = message.CipherSuite;

        DeriveKey(message.KeyShare);

        State = TlsState.WaitEncryptedExtensions;
    }

    void ReceiveEncryptedExtensions(EncryptedExtensionsMessage message) {
        if(State != TlsState.WaitEncryptedExtensions)
            throw new QuicException();

        State = TlsState.WaitCertificate;
    }

    void ReceiveCertificate(CertificateMessage message) {
        if(State != TlsState.WaitCertificate)
            throw new QuicException();

        remoteCertificateChain = message.CertificateChain;

        State = TlsState.WaitCertificateVerify;
    }

    void ReceiveCertificateVerify(CertificateVerifyMessage message) {
        if(State != TlsState.WaitCertificateVerify)
            throw new QuicException();

        if(!CertificateVerifyMessage.Verify(EndpointType.Server, remoteCertificateChain[0], message.SignatureScheme, message.Signature, GetMessagesHash(HashUtils.GetName(CipherSuite))))
            throw new QuicException();

        State = TlsState.WaitServerFinished;
    }

    void ReceiveFinished(FinishedMessage message) {
        if(State != TlsState.WaitServerFinished && State != TlsState.WaitClientFinished)
            throw new QuicException();

        HashAlgorithmName name = HashUtils.GetName(CipherSuite);

        if(!message.Verify(name, GetMessagesHash(name), State == TlsState.WaitServerFinished ? serverHandshakeSecret : clientHandshakeSecret))
            throw new QuicException();

        State = TlsState.Connected;
    }

    void DeriveKey(KeyShareExtension.KeyShareEntry[] keyShare) {
        X25519PublicKeyParameters key = new(keyShare.First(key => key.NamedGroup == NamedGroup.X25519).Key);

        X25519Agreement agreement = new();

        agreement.Init(keyPair.Private);

        agreement.CalculateAgreement(key, this.key);
    }

    void GetMessagesHash(HashAlgorithmName name, Span<byte> hash) {
        messages.Position = 0;

        if(name == HashAlgorithmName.SHA256)
            SHA256.HashData(messages, hash);
        else if(name == HashAlgorithmName.SHA384)
            SHA384.HashData(messages, hash);
        else
            throw new ArgumentOutOfRangeException(nameof(name));

        messages.Position = messages.Length;
    }

    byte[] GetMessagesHash(HashAlgorithmName name) {
        byte[] hash = new byte[HashUtils.GetLength(name)];

        GetMessagesHash(name, hash);

        return hash;
    }

    public enum TlsState {
        Start,
        WaitServerHello,
        WaitEncryptedExtensions,
        WaitCertificate,
        WaitCertificateVerify,
        WaitServerFinished,
        WaitClientFinished,
        Connected
    }
}
