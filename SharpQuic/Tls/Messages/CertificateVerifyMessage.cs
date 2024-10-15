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

    public byte[] Signature { get; set; }

    static CertificateVerifyMessage() {
        Span<byte> repeations = stackalloc byte[64];

        repeations.Fill(0x20);

        string clientContextString = "TLS 1.3, client CertificateVerify";

        Span<byte> context = stackalloc byte[Encoding.ASCII.GetByteCount(clientContextString)];

        Encoding.ASCII.GetBytes(clientContextString, context);

        ClientSignatureStart = [..repeations, ..context, 0];

        string serverContextString = "TLS 1.3, server CertificateVerify";

        context = stackalloc byte[Encoding.ASCII.GetByteCount(serverContextString)];

        Encoding.ASCII.GetBytes(serverContextString, context);

        ServerSignatureStart = [..repeations, ..context, 0];
    }

    public static CertificateVerifyMessage Create(EndpointType endpointType, byte[] messages, X509Certificate2 certificate) {
        byte[] signature = GetSignature(endpointType, messages);

        using RSA rsa = certificate.GetRSAPrivateKey();
        
        if(rsa is not null)
            signature = rsa.SignHash(signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        else {
            using ECDsa ecdsa = certificate.GetECDsaPrivateKey();

            signature = ecdsa.SignHash(signature);
        }

        return new() {
            Signature = signature
        };
    }

    public void Encode(Stream stream) {
        Serializer.WriteUInt16(stream, (ushort)SignatureScheme.RSAPkcs1SHA256);

        Serializer.WriteUInt16(stream, (ushort)Signature.Length);
        stream.Write(Signature);
    }

    public static CertificateVerifyMessage Decode(Stream stream) {
        stream.Position += 2;

        int length = Serializer.ReadUInt16(stream);

        CertificateVerifyMessage message = new() {
            Signature = new byte[length]
        };

        stream.ReadExactly(message.Signature);

        return message;
    }

    public static bool Verify(EndpointType endpointType, X509Certificate2 certificate, byte[] signature, ReadOnlySpan<byte> messages) {
        using RSA rsa = certificate.PublicKey.GetRSAPublicKey();

        if(rsa is not null)
            return rsa.VerifyHash(GetSignature(endpointType, messages), signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        using ECDsa ecdsa = certificate.PublicKey.GetECDsaPublicKey();

        return ecdsa.VerifyHash(GetSignature(endpointType, messages), signature, DSASignatureFormat.Rfc3279DerSequence);
    }

    static byte[] GetSignature(EndpointType endpointType, ReadOnlySpan<byte> messages) {
        Span<byte> signature = [..(endpointType == EndpointType.Client ? ClientSignatureStart : ServerSignatureStart), ..messages];

        return SHA256.HashData(signature);
    }
}
