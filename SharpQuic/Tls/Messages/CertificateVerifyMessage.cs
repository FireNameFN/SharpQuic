using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SharpQuic.Tls.Messages;

public sealed class CertificateVerifyMessage : IMessage {
    static readonly byte[] ClientSignatureStart;

    static readonly byte[] ServerSignatureStart;

    public HandshakeType Type { get; } = HandshakeType.CertificateVerify;

    public EndpointType EndpointType { get; set; }

    public byte[] Messages { get; set; }

    public X509Certificate2 Certificate { get; set; }

    public byte[] Signature { get; set; }

    static CertificateVerifyMessage() {
        Span<byte> repeations = stackalloc byte[64];

        repeations.Fill(20);

        string clientContextString = "TLS 1.3, client CertificateVerify";

        Span<byte> context = stackalloc byte[Encoding.ASCII.GetByteCount(clientContextString)];

        Encoding.ASCII.GetBytes(clientContextString, context);

        ClientSignatureStart = [..repeations, ..context, 0];

        string serverContextString = "TLS 1.3, server CertificateVerify";

        context = stackalloc byte[Encoding.ASCII.GetByteCount(serverContextString)];

        Encoding.ASCII.GetBytes(serverContextString, context);

        ServerSignatureStart = [..repeations, ..context, 0];
    }

    public void Encode(Stream stream) {
        Serializer.WriteUInt16(stream, (ushort)SignatureScheme.RSAPkcs1SHA256);

        byte[] signature = GetSignature(EndpointType, Messages);

        using RSA rsa = RSA.Create();

        RSAPKCS1SignatureFormatter formatter = new(Certificate.GetRSAPrivateKey());

        formatter.SetHashAlgorithm("SHA256");

        signature = formatter.CreateSignature(signature);

        Serializer.WriteUInt16(stream, (ushort)signature.Length);
        stream.Write(signature);
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
        RSAPKCS1SignatureDeformatter deformatter = new(certificate.PublicKey.GetRSAPublicKey());

        deformatter.SetHashAlgorithm("SHA256");

        return deformatter.VerifySignature(GetSignature(endpointType, messages), signature);
    }

    static byte[] GetSignature(EndpointType endpointType, ReadOnlySpan<byte> messages) {
        Span<byte> hash = stackalloc byte[32];

        SHA256.HashData(messages, hash);

        Span<byte> signature = [..(endpointType == EndpointType.Client ? ClientSignatureStart : ServerSignatureStart), ..hash];

        return SHA256.HashData(signature);
    }
}
