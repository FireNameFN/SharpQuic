using System;
using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using SharpQuic.Packets;

namespace SharpQuic;

public sealed class QuicPacketProtection {
    readonly byte[] sourceKey = new byte[16];

    readonly byte[] sourceIv = new byte[12];

    readonly byte[] sourceHp = new byte[16];

    readonly byte[] destinationKey = new byte[16];

    readonly byte[] destinationIv = new byte[12];

    readonly byte[] destinationHp = new byte[16];

    public QuicPacketProtection(EndpointType type, byte[] sourceConnectionId, byte[] destinationConnectionId) {
        Span<byte> initialSalt = stackalloc byte[32];

        Converter.HexToBytes("38762cf7f55934b34d179ae6a4c80cadccbb7f0a", initialSalt);

        Span<byte> initialSecret = stackalloc byte[32];

        HKDF.Extract(HashAlgorithmName.SHA256, destinationConnectionId, initialSalt, initialSecret);

        Span<byte> sourceInitialSecret = stackalloc byte[32];

        HKDFExtensions.ExpandLabel(initialSecret, type == EndpointType.Client ? "client in" : "server in", sourceInitialSecret);

        HKDFExtensions.ExpandLabel(sourceInitialSecret, "quic key", sourceKey);
        HKDFExtensions.ExpandLabel(sourceInitialSecret, "quic iv", sourceIv);
        HKDFExtensions.ExpandLabel(sourceInitialSecret, "quic hp", sourceHp);

        HKDF.Extract(HashAlgorithmName.SHA256, sourceConnectionId, initialSalt, initialSecret);

        Span<byte> destinationInitialSecret = stackalloc byte[32];

        HKDFExtensions.ExpandLabel(initialSecret, type == EndpointType.Client ? "server in" : "client in", destinationInitialSecret);

        HKDFExtensions.ExpandLabel(destinationInitialSecret, "quic key", destinationKey);
        HKDFExtensions.ExpandLabel(destinationInitialSecret, "quic iv", destinationIv);
        HKDFExtensions.ExpandLabel(destinationInitialSecret, "quic hp", destinationHp);
    }

    public byte[] Protect(InitialPacket packet) {
        Span<byte> nonce = stackalloc byte[sourceIv.Length];

        GetNonce(sourceIv, packet.PacketNumber, nonce);

        Span<byte> payload = stackalloc byte[packet.Payload.Length];

        Span<byte> tag = stackalloc byte[16];

        AesGcm aesGcm = new(sourceKey, 16);

        aesGcm.Encrypt(nonce, packet.Payload, payload, tag, packet.EncodeUnprotectedHeader());

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

    public InitialPacket Unprotect(byte[] packetArray) {
        InitialPacket packet = new();

        MemoryStream stream = new(packetArray);

        byte protectedFirstByte = Serializer.ReadByte(stream);

        stream.Position += 4;

        packet.DestinationConnectionId = new byte[Serializer.ReadByte(stream)];

        stream.Read(packet.DestinationConnectionId);

        packet.SourceConnectionId = new byte[Serializer.ReadByte(stream)];

        stream.Read(packet.SourceConnectionId);

        packet.Token = new byte[Serializer.ReadVariableLength(stream)];

        stream.Read(packet.Token);

        Span<byte> remainder = stackalloc byte[(int)Serializer.ReadVariableLength(stream)];

        stream.Read(remainder);

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

    void GetNonce(ReadOnlySpan<byte> iv, uint packetNumber, Span<byte> nonce) {
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

    public enum EndpointType {
        Client,
        Server
    }
}
