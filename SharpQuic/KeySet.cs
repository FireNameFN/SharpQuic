using System;
using System.Security.Cryptography;
using SharpQuic.Tls;
using SharpQuic.Tls.Enums;

namespace SharpQuic;

public class KeySet(CipherSuite cipherSuite) {
    public CipherSuite CipherSuite { get; } = cipherSuite;

    public byte[] SourceKey { get; } = new byte[cipherSuite == CipherSuite.Aes128GcmSHA256 ? 16 : 32];

    public byte[] SourceIv { get; } = new byte[12];

    public byte[] SourceHp { get; } = new byte[cipherSuite == CipherSuite.Aes128GcmSHA256 ? 16 : 32];

    public byte[] DestinationKey { get; } = new byte[cipherSuite == CipherSuite.Aes128GcmSHA256 ? 16 : 32];

    public byte[] DestinationIv { get; } = new byte[12];

    public byte[] DestinationHp { get; } = new byte[cipherSuite == CipherSuite.Aes128GcmSHA256 ? 16 : 32];

    public void Generate(ReadOnlySpan<byte> sourceSecret, ReadOnlySpan<byte> destinationSecret) {
        HashAlgorithmName name = HashUtils.GetName(CipherSuite);

        HKDFExtensions.ExpandLabel(name, sourceSecret, "quic key", SourceKey);
        HKDFExtensions.ExpandLabel(name, sourceSecret, "quic iv", SourceIv);
        HKDFExtensions.ExpandLabel(name, sourceSecret, "quic hp", SourceHp);

        HKDFExtensions.ExpandLabel(name, destinationSecret, "quic key", DestinationKey);
        HKDFExtensions.ExpandLabel(name, destinationSecret, "quic iv", DestinationIv);
        HKDFExtensions.ExpandLabel(name, destinationSecret, "quic hp", DestinationHp);
    }
}
