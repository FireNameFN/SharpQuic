using System;
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
        HKDFExtensions.ExpandLabel(sourceSecret, "quic key", SourceKey);
        HKDFExtensions.ExpandLabel(sourceSecret, "quic iv", SourceIv);
        HKDFExtensions.ExpandLabel(sourceSecret, "quic hp", SourceHp);

        HKDFExtensions.ExpandLabel(destinationSecret, "quic key", DestinationKey);
        HKDFExtensions.ExpandLabel(destinationSecret, "quic iv", DestinationIv);
        HKDFExtensions.ExpandLabel(destinationSecret, "quic hp", DestinationHp);
    }
}
