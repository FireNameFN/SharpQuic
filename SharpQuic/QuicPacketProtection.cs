using System;
using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using SharpQuic.Packets;
using SharpQuic.Tls;

namespace SharpQuic;

public sealed class QuicPacketProtection(EndpointType endpointType) {
    static readonly byte[] InitialSalt = new byte[32];

    public EndpointType EndpointType { get; } = endpointType;

    public CipherSuite CipherSuite { get; set; } = CipherSuite.Aes128GcmSha256;

    internal readonly byte[] sourceKey = new byte[16];

    internal readonly byte[] sourceIv = new byte[12];

    internal readonly byte[] sourceHp = new byte[16];

    internal readonly byte[] destinationKey = new byte[16];

    internal readonly byte[] destinationIv = new byte[12];

    internal readonly byte[] destinationHp = new byte[16];

    static QuicPacketProtection() {
        Converter.HexToBytes("38762cf7f55934b34d179ae6a4c80cadccbb7f0a", InitialSalt);
    }

    public void GenerateInitialKeys(byte[] sourceConnectionId, byte[] destinationConnectionId) {
        Span<byte> initialSecret = stackalloc byte[32];

        HKDF.Extract(HashAlgorithmName.SHA256, destinationConnectionId, InitialSalt, initialSecret);

        Span<byte> clientInitialSecret = stackalloc byte[32];

        HKDFExtensions.ExpandLabel(initialSecret, "client in", clientInitialSecret);

        HKDF.Extract(HashAlgorithmName.SHA256, sourceConnectionId, InitialSalt, initialSecret);

        Span<byte> serverInitialSecret = stackalloc byte[32];

        HKDFExtensions.ExpandLabel(initialSecret, "server in", serverInitialSecret);

        GenerateKeys(clientInitialSecret, serverInitialSecret);
    }

    public void GenerateKeys(ReadOnlySpan<byte> clientSecret, ReadOnlySpan<byte> serverSecret) {
        HKDFExtensions.ExpandLabel(clientSecret, "quic key", EndpointType == EndpointType.Client ? sourceKey : destinationKey);
        HKDFExtensions.ExpandLabel(clientSecret, "quic iv", EndpointType == EndpointType.Client ? sourceIv : destinationIv);
        HKDFExtensions.ExpandLabel(clientSecret, "quic hp", EndpointType == EndpointType.Client ? sourceHp : destinationHp);

        HKDFExtensions.ExpandLabel(serverSecret, "quic key", EndpointType == EndpointType.Server ? sourceKey : destinationKey);
        HKDFExtensions.ExpandLabel(serverSecret, "quic iv", EndpointType == EndpointType.Server ? sourceIv : destinationIv);
        HKDFExtensions.ExpandLabel(serverSecret, "quic hp", EndpointType == EndpointType.Server ? sourceHp : destinationHp);
    }

    public byte[] Protect(LongHeaderPacket packet) {
        Span<byte> nonce = stackalloc byte[sourceIv.Length];

        GetNonce(sourceIv, packet.PacketNumber, nonce);

        Span<byte> payload = stackalloc byte[packet.Payload.Length];

        Span<byte> tag = stackalloc byte[16];

        switch(CipherSuite) {
            case CipherSuite.Aes128GcmSha256:
                AesGcm aesGcm = new(sourceKey, 16);

                aesGcm.Encrypt(nonce, packet.Payload, payload, tag, packet.EncodeUnprotectedHeader());

                break;
        }

        int packetNumberLength = packet.GetPacketNumberLength();

        Span<byte> sample = payload.Slice(4 - packetNumberLength, 16);

        Span<byte> mask = stackalloc byte[16];

        GetMask(sourceHp, sample, mask);

        byte protectedFirstByte = (byte)(packet.GetUnprotectedFirstByte() ^ mask[0]);

        Span<byte> packetNumberSpan = stackalloc byte[sizeof(uint)];

        BinaryPrimitives.WriteUInt32BigEndian(packetNumberSpan, packet.PacketNumber);

        int start = packetNumberSpan.Length - packetNumberLength;

        for(int i = start; i < packetNumberSpan.Length; i++)
            packetNumberSpan[i] = (byte)(packetNumberSpan[i] ^ mask[i - start + 1]);

        uint protectedPacketNumber = BinaryPrimitives.ReadUInt32BigEndian(packetNumberSpan);

        MemoryStream stream = new();

        Serializer.WriteByte(stream, protectedFirstByte);

        stream.Write(packet.EncodePublicHeader());

        Serializer.WriteWithLength(stream, protectedPacketNumber, packetNumberLength);

        stream.Write(payload);

        stream.Write(tag);

        return stream.ToArray();
    }

    public LongHeaderPacket Unprotect(byte[] packetArray) {
        MemoryStream stream = new(packetArray);

        byte protectedFirstByte = Serializer.ReadByte(stream);

        LongHeaderPacket packet = (protectedFirstByte & 0b11110000) switch {
            0b11000000 => new InitialPacket(),
            0b11110000 => new HandshakePacket(),
            _ => throw new QuicException()
        };

        stream.Position += 4;

        packet.DestinationConnectionId = new byte[Serializer.ReadByte(stream)];

        stream.ReadExactly(packet.DestinationConnectionId);

        packet.SourceConnectionId = new byte[Serializer.ReadByte(stream)];

        stream.ReadExactly(packet.SourceConnectionId);

        if(packet is InitialPacket initialPacket) {
            initialPacket.Token = new byte[Serializer.ReadVariableLength(stream)];

            stream.ReadExactly(initialPacket.Token);
        }

        Span<byte> remainder = stackalloc byte[(int)Serializer.ReadVariableLength(stream)];

        stream.ReadExactly(remainder);

        Span<byte> sample = remainder.Slice(4, 16);

        Span<byte> mask = stackalloc byte[16];

        GetMask(destinationHp, sample, mask);

        int packetNumberLength = ((protectedFirstByte ^ mask[0]) & 0b00111111) + 1;

        Span<byte> packetNumberSpan = stackalloc byte[sizeof(uint)];

        remainder[..packetNumberLength].CopyTo(packetNumberSpan[^packetNumberLength..]);

        packet.PacketNumberLength = packetNumberLength;

        packet.PacketNumber = MaskPacketNumber(mask, packetNumberLength, packetNumberSpan);

        Span<byte> nonce = stackalloc byte[destinationIv.Length];

        GetNonce(destinationIv, packet.PacketNumber, nonce);

        Span<byte> payload = remainder[packetNumberLength..^16];

        packet.Payload = new byte[payload.Length];

        AesGcm aesGcm = new(destinationKey, 16);

        aesGcm.Decrypt(nonce, payload, remainder[^16..], packet.Payload, packet.EncodeUnprotectedHeader());

        return packet;
    }

    static void GetNonce(ReadOnlySpan<byte> iv, uint packetNumber, Span<byte> nonce) {
        Span<byte> packetNumberSpan = stackalloc byte[nonce.Length];

        BinaryPrimitives.WriteUInt32BigEndian(packetNumberSpan[^sizeof(uint)..], packetNumber);

        for(int i = 0; i < nonce.Length; i++)
            nonce[i] = (byte)(iv[i] ^ packetNumberSpan[i]);
    }

    static void GetMask(byte[] hp, ReadOnlySpan<byte> sample, Span<byte> mask) {
        Aes aes = Aes.Create();

        aes.Key = hp;

        aes.EncryptEcb(sample, mask, PaddingMode.None);

        mask[0] &= 0b1111;
    }

    static uint MaskPacketNumber(ReadOnlySpan<byte> mask, int packetNumberLength, Span<byte> packetNumberSpan) {
        int start = packetNumberSpan.Length - packetNumberLength;

        for(int i = start; i < packetNumberSpan.Length; i++)
            packetNumberSpan[i] = (byte)(packetNumberSpan[i] ^ mask[i - start + 1]);

        return BinaryPrimitives.ReadUInt32BigEndian(packetNumberSpan);
    }
}
