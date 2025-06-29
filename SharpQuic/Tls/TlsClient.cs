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
    public TlsState State { get; private set; }

    public CipherSuite CipherSuite { get; private set; }

    public QuicTransportParameters PeerParameters { get; private set; }

    public string Protocol { get; private set; }

    public bool ClientAuthenticationRequested { get; private set; }

    bool client;

    readonly QuicTransportParameters parameters;

    string[] protocols;

    X509Certificate2[] certificateChain;

    X509ChainPolicy chainPolicy;

    bool clientAuthentication;

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

    public TlsClient(QuicTransportParameters parameters, string[] protocols, X509Certificate2[] certificateChain = null, X509ChainPolicy chainPolicy = null, bool clientAuthentication = false) {
        this.parameters = parameters;
        this.protocols = protocols;
        this.certificateChain = certificateChain ?? [];
        this.chainPolicy = chainPolicy ?? new();
        this.clientAuthentication = clientAuthentication;

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

    public byte[] SendClientHello() {
        byte[] key = new byte[32];

        ((X25519PublicKeyParameters)keyPair.Public).Encode(key);

        byte[] k = new byte[32];

        byte[] k1 = new byte[32];

        ((ECPublicKeyParameters)keyPair1.Public).Q.XCoord.GetEncoded().AsSpan().CopyTo(k);

        ((ECPublicKeyParameters)keyPair1.Public).Q.XCoord.GetEncoded().AsSpan().CopyTo(k1); // TODO Maybe YCoord?

        byte[] key1 = [4, ..k, ..k1];

        ClientHelloMessage message = new() {
            CipherSuites = [CipherSuite.ChaCha20Poly1305Sha256, CipherSuite.Aes256GcmSHA384, CipherSuite.Aes128GcmSHA256],
            KeyShare = [new(NamedGroup.X25519, key), new(NamedGroup.SecP256r1, key1)],
            Protocols = protocols,
            Parameters = parameters
        };

        State = TlsState.WaitingServerHello;

        client = true;

        return GetHandshake(message);
    }

    public byte[] SendServerHello() {
        byte[] key = new byte[32];

        ((X25519PublicKeyParameters)keyPair.Public).Encode(key);

        ServerHelloMessage message = new() {
            CipherSuite = CipherSuite,
            KeyShare = [new(NamedGroup.X25519, key)]
        };

        return GetHandshake(message);
    }

    public byte[] SendServerHandshake() {
        MemoryStream stream = new();

        EncryptedExtensionsMessage encryptedExtensionsMessage = new() {
            Protocol = Protocol,
            Parameters = parameters
        };

        stream.Write(GetHandshake(encryptedExtensionsMessage));

        CertificateMessage certificateMessage = new() {
            CertificateChain = certificateChain
        };

        stream.Write(GetHandshake(certificateMessage));

        if(certificateChain.Length > 0) {
            HashAlgorithmName name = HashUtils.GetName(CipherSuite);

            CertificateVerifyMessage certificateVerifyMessage = CertificateVerifyMessage.Create(EndpointType.Server, GetMessagesHash(name), certificateChain[0]);

            stream.Write(GetHandshake(certificateVerifyMessage));
        }

        return stream.ToArray();
    }

    public byte[] SendCertificateRequest() {
        CertificateRequestMessage certificateRequestMessage = new();

        State = TlsState.WaitingCertificate;

        return GetHandshake(certificateRequestMessage);
    }

    public byte[] SendServerFinished() {
        HashAlgorithmName name = HashUtils.GetName(CipherSuite);

        FinishedMessage finishedMessage = FinishedMessage.Create(name, GetMessagesHash(name), serverHandshakeSecret);

        State = TlsState.WaitingFinished;

        return GetHandshake(finishedMessage);
    }

    public byte[] SendClientCertificate() {
        MemoryStream stream = new();

        CertificateMessage certificateMessage = new() {
            CertificateChain = certificateChain
        };

        stream.Write(GetHandshake(certificateMessage));

        if(certificateChain.Length > 0) {
            HashAlgorithmName name = HashUtils.GetName(CipherSuite);

            CertificateVerifyMessage certificateVerifyMessage = CertificateVerifyMessage.Create(EndpointType.Server, GetMessagesHash(name), certificateChain[0]);

            stream.Write(GetHandshake(certificateVerifyMessage));
        }

        State = TlsState.WaitingFinished;

        return stream.ToArray();
    }

    public byte[] SendClientFinished() {
        HashAlgorithmName name = HashUtils.GetName(CipherSuite);

        FinishedMessage finishedMessage = FinishedMessage.Create(name, GetMessagesHash(name), clientHandshakeSecret);

        return GetHandshake(finishedMessage);
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
            case HandshakeType.CertificateRequest:
                ReceiveCertificateRequest(CertificateRequestMessage.Decode(stream));
                Console.WriteLine("Received CertificateRequest");
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
                throw new QuicException();
        }

        if(state == TlsState.WaitingFinished && !client)
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

        PeerParameters = message.Parameters;

        Protocol = protocols.Intersect(message.Protocols).FirstOrDefault();

        if(Protocol is null)
            throw new QuicException();

        State = TlsState.WaitingFinished;
    }

    void ReceiveServerHello(ServerHelloMessage message) {
        if(State != TlsState.WaitingServerHello)
            throw new QuicException();

        CipherSuite = message.CipherSuite;

        DeriveKey(message.KeyShare);

        State = TlsState.WaitingEncryptedExtensions;
    }

    void ReceiveEncryptedExtensions(EncryptedExtensionsMessage message) {
        if(State != TlsState.WaitingEncryptedExtensions)
            throw new QuicException();

        Protocol = message.Protocol;

        PeerParameters = message.Parameters;

        State = TlsState.WaitingCertificate;
    }

    void ReceiveCertificate(CertificateMessage message) {
        if(State != TlsState.WaitingCertificate)
            throw new QuicException();

        remoteCertificateChain = message.CertificateChain;

        chainPolicy.ExtraStore.AddRange(message.CertificateChain);

        using X509Chain chain = new() {
            ChainPolicy = chainPolicy
        };

        if(!chain.Build(message.CertificateChain[0]))
            throw new QuicException();

        State = TlsState.WaitingCertificateVerify;
    }

    void ReceiveCertificateRequest(CertificateRequestMessage message) {
        if(State != TlsState.WaitingFinishedOrCertificateRequest || !client)
            throw new QuicException();

        ClientAuthenticationRequested = true;
    }

    void ReceiveCertificateVerify(CertificateVerifyMessage message) {
        if(State != TlsState.WaitingCertificateVerify)
            throw new QuicException();

        if(!CertificateVerifyMessage.Verify(EndpointType.Server, remoteCertificateChain[0], message.SignatureScheme, message.Signature, GetMessagesHash(HashUtils.GetName(CipherSuite))))
            throw new QuicException();

        State = TlsState.WaitingFinishedOrCertificateRequest;
    }

    void ReceiveFinished(FinishedMessage message) {
        if(State != TlsState.WaitingFinishedOrCertificateRequest && State != TlsState.WaitingFinished)
            throw new QuicException();

        HashAlgorithmName name = HashUtils.GetName(CipherSuite);

        if(!message.Verify(name, GetMessagesHash(name), client ? serverHandshakeSecret : clientHandshakeSecret))
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
        WaitingServerHello,
        WaitingEncryptedExtensions,
        WaitingCertificate,
        WaitingCertificateVerify,
        WaitingFinishedOrCertificateRequest,
        WaitingFinished,
        Connected
    }
}
