using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SharpQuic.Tls.Enums;

namespace SharpQuic.Tls.Messages;

public sealed class CertificateVerifyMessage : IMessage {
    static readonly byte[] ClientSignatureStart;

    static readonly byte[] ServerSignatureStart;

    public HandshakeType Type { get; } = HandshakeType.CertificateVerify;

    public SignatureScheme SignatureScheme { get; set; }

    public byte[] Signature { get; set; }

    static CertificateVerifyMessage() {
        Span<byte> repeations = stackalloc byte[64];

        repeations.Fill(0x20);

        string clientContextString = "TLS 1.3, client CertificateVerify";

        string serverContextString = "TLS 1.3, server CertificateVerify";

        Span<byte> context = stackalloc byte[Encoding.ASCII.GetMaxByteCount(Math.Max(clientContextString.Length, serverContextString.Length))];

        int length = Encoding.ASCII.GetBytes(clientContextString, context);

        ClientSignatureStart = [..repeations, ..context[..length], 0];

        length = Encoding.ASCII.GetBytes(serverContextString, context);

        ServerSignatureStart = [..repeations, ..context[..length], 0];
    }

    public static CertificateVerifyMessage Create(EndpointType endpointType, byte[] messages, X509Certificate2 certificate) {
        byte[] signature = GetSignature(endpointType, messages);

        SignatureScheme signatureScheme;

        using RSA rsa = certificate.GetRSAPrivateKey();
        
        if(rsa is not null) {
            signatureScheme = SignatureScheme.RSAPkcs1SHA256;

            signature = rsa.SignHash(signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        } else {
            signatureScheme = SignatureScheme.ECDSASecp256r1SHA256;

            using ECDsa ecdsa = certificate.GetECDsaPrivateKey();

            signature = ecdsa.SignHash(signature);
        }

        return new() {
            SignatureScheme = signatureScheme,
            Signature = signature
        };
    }

    public void Encode(Stream stream) {
        Serializer.WriteUInt16(stream, (ushort)SignatureScheme);

        Serializer.WriteUInt16(stream, (ushort)Signature.Length);
        stream.Write(Signature);
    }

    public static CertificateVerifyMessage Decode(Stream stream) {
        SignatureScheme signatureScheme = (SignatureScheme)Serializer.ReadUInt16(stream);

        int length = Serializer.ReadUInt16(stream);

        CertificateVerifyMessage message = new() {
            SignatureScheme = signatureScheme,
            Signature = new byte[length]
        };

        stream.ReadExactly(message.Signature);

        return message;
    }

    public static bool Verify(EndpointType endpointType, X509Certificate2 certificate, SignatureScheme signatureScheme, byte[] signature, ReadOnlySpan<byte> messages) {
        switch(signatureScheme) {
            case SignatureScheme.RSAPkcs1SHA256:
                using(RSA rsa = certificate.PublicKey.GetRSAPublicKey())
                    return rsa.VerifyHash(GetSignature(endpointType, messages), signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            case SignatureScheme.RSAPssRsaeSHA256:
                using(RSA rsa = certificate.PublicKey.GetRSAPublicKey())
                    return rsa.VerifyHash(GetSignature(endpointType, messages), signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            case SignatureScheme.ECDSASecp256r1SHA256:
                using(ECDsa ecdsa = certificate.PublicKey.GetECDsaPublicKey())
                    return ecdsa.VerifyHash(GetSignature(endpointType, messages), signature, DSASignatureFormat.Rfc3279DerSequence);
            default:
                throw new QuicException();
        }
    }

    static byte[] GetSignature(EndpointType endpointType, ReadOnlySpan<byte> messages) {
        Span<byte> signature = [..(endpointType == EndpointType.Client ? ClientSignatureStart : ServerSignatureStart), ..messages];

        return SHA256.HashData(signature);
    }
}
