using System;
using System.Buffers.Binary;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using SharpQuic.Packets;
using SharpQuic.Tls;
using SharpQuic.Tls.Enums;

namespace SharpQuic;

public sealed class QuicPacketProtection(EndpointType endpointType, byte[] sourceConnectionId) {
    static readonly byte[] InitialSalt = Converter.HexToBytes("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");

    public EndpointType EndpointType { get; } = endpointType;

    public CipherSuite CipherSuite { get; set; } = CipherSuite.Aes128GcmSHA256;

    readonly byte[] sourceConnectionId = sourceConnectionId;

    bool initialKeysGenerated;

    void GenerateInitialKeys(byte[] clientDestinationConnectionId, KeySet keySet) {
        Span<byte> initialSecret = stackalloc byte[32];

        HKDF.Extract(HashAlgorithmName.SHA256, clientDestinationConnectionId, InitialSalt, initialSecret);

        Span<byte> clientInitialSecret = stackalloc byte[32];

        HKDFExtensions.ExpandLabel(initialSecret, "client in", clientInitialSecret);

        Span<byte> serverInitialSecret = stackalloc byte[32];

        HKDFExtensions.ExpandLabel(initialSecret, "server in", serverInitialSecret);
        
        if(EndpointType == EndpointType.Client)
            keySet.Generate(clientInitialSecret, serverInitialSecret);
        else
            keySet.Generate(serverInitialSecret, clientInitialSecret);

        initialKeysGenerated = true;
    }

    public byte[] Protect(Packet packet, KeySet initialKeySet, KeySet handshakeKeySet, KeySet applicationKeySet) {
        KeySet keySet = packet.PacketType switch {
            PacketType.Initial => initialKeySet,
            PacketType.Retry => initialKeySet,
            PacketType.Handshake => handshakeKeySet,
            PacketType.OneRtt => applicationKeySet,
            PacketType.OneRttSpin => applicationKeySet,
            _ => throw new NotImplementedException()
        };

        if(!initialKeysGenerated && packet is InitialPacket)
            GenerateInitialKeys(packet.DestinationConnectionId, keySet);

        Span<byte> nonce = stackalloc byte[keySet.SourceIv.Length];

        GetNonce(keySet.SourceIv, packet.PacketNumber, nonce);

        Span<byte> payload = stackalloc byte[packet.Payload.Length];

        Span<byte> tag = stackalloc byte[16];

        switch(CipherSuite) {
            case CipherSuite.Aes128GcmSHA256:
            case CipherSuite.Aes256GcmSHA384:
                using(AesGcm aesGcm = new(keySet.SourceKey, 16))
                    aesGcm.Encrypt(nonce, packet.Payload, payload, tag, packet.EncodeUnprotectedHeader());

                break;
        }

        int packetNumberLength = packet.GetPacketNumberLength();

        Span<byte> sample = payload.Slice(4 - packetNumberLength, 16);

        Span<byte> mask = stackalloc byte[16];

        GetMask(keySet.SourceHp, sample, packet.PacketType, mask);

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

    public Packet Unprotect(Stream stream, KeySet initialKeySet, KeySet handshakeKeySet, KeySet applicationKeySet) {
        byte protectedFirstByte = Serializer.ReadByte(stream);

        PacketType type = (PacketType)(protectedFirstByte & 0b11110000);

        (Packet packet, KeySet keySet) = type switch {
            PacketType.Initial => ((Packet)new InitialPacket(), initialKeySet),
            PacketType.Retry => (new RetryPacket(), initialKeySet),
            PacketType.Handshake => (new HandshakePacket(), handshakeKeySet),
            _ => (null, null)
        };

        if(packet is null) {
            type = (PacketType)(protectedFirstByte & 0b11100000);

            packet = type switch {
                PacketType.OneRtt => new OneRttPacket(),
                PacketType.OneRttSpin => new OneRttPacket(),
                0 => null,
                _ => throw new NotImplementedException()
            };

            if(packet is null)
                return null;
        }

        int destinationConnectionIdLength;

        if(packet is LongHeaderPacket) {
            stream.Position += 4;

            destinationConnectionIdLength = Serializer.ReadByte(stream);
        } else
            destinationConnectionIdLength = sourceConnectionId.Length;

        packet.DestinationConnectionId = new byte[destinationConnectionIdLength];

        stream.ReadExactly(packet.DestinationConnectionId);

        if(packet is not InitialPacket && !packet.DestinationConnectionId.SequenceEqual(sourceConnectionId))
            return null;

        if(packet is LongHeaderPacket longHeaderPacket) {
            longHeaderPacket.SourceConnectionId = new byte[Serializer.ReadByte(stream)];

            stream.ReadExactly(longHeaderPacket.SourceConnectionId);

            if(packet is InitialPacket initialPacket) {
                (ulong tokenLength, initialPacket.TokenLengthLength) = Serializer.ReadVariableLength(stream);
                
                initialPacket.Token = new byte[tokenLength];

                stream.ReadExactly(initialPacket.Token);

                if(!initialKeysGenerated && EndpointType == EndpointType.Server)
                    GenerateInitialKeys(packet.DestinationConnectionId, keySet);
            } else if(packet is RetryPacket retryPacket) {
                retryPacket.Token = new byte[stream.Length - stream.Position - 16];

                stream.ReadExactly(retryPacket.Token);

                stream.Position += 16;

                return packet;
            }
        }

        (ulong length, packet.LengthLength) = Serializer.ReadVariableLength(stream);

        Span<byte> remainder = stackalloc byte[(int)length];

        stream.ReadExactly(remainder);

        Span<byte> sample = remainder.Slice(4, 16);

        Span<byte> mask = stackalloc byte[16];

        GetMask(keySet.DestinationHp, sample, type, mask);

        int packetNumberLength = ((protectedFirstByte ^ mask[0]) & 0b11) + 1;

        Span<byte> packetNumberSpan = stackalloc byte[sizeof(uint)];

        remainder[..packetNumberLength].CopyTo(packetNumberSpan[^packetNumberLength..]);

        packet.PacketNumberLength = packetNumberLength;

        packet.PacketNumber = MaskPacketNumber(mask, packetNumberLength, packetNumberSpan);

        Span<byte> nonce = stackalloc byte[keySet.DestinationIv.Length];

        GetNonce(keySet.DestinationIv, packet.PacketNumber, nonce);

        Span<byte> payload = remainder[packetNumberLength..^16];

        packet.Payload = new byte[payload.Length];

        switch(CipherSuite) {
            case CipherSuite.Aes128GcmSHA256:
            case CipherSuite.Aes256GcmSHA384:
                using(AesGcm aesGcm = new(keySet.DestinationKey, 16))
                    aesGcm.Decrypt(nonce, payload, remainder[^16..], packet.Payload, packet.EncodeUnprotectedHeader());

                break;
            default:
                throw new NotImplementedException();
        }

        return packet;
    }

    static void GetNonce(ReadOnlySpan<byte> iv, uint packetNumber, Span<byte> nonce) {
        Span<byte> packetNumberSpan = stackalloc byte[nonce.Length];

        BinaryPrimitives.WriteUInt32BigEndian(packetNumberSpan[^sizeof(uint)..], packetNumber);

        for(int i = 0; i < nonce.Length; i++)
            nonce[i] = (byte)(iv[i] ^ packetNumberSpan[i]);
    }

    static void GetMask(byte[] hp, ReadOnlySpan<byte> sample, PacketType type, Span<byte> mask) {
        using Aes aes = Aes.Create();

        aes.Key = hp;

        aes.EncryptEcb(sample, mask, PaddingMode.None);

        mask[0] &= type.HasFlag(PacketType.LongHeader) ? (byte)0b1111 : (byte)0b11111;
    }

    static uint MaskPacketNumber(ReadOnlySpan<byte> mask, int packetNumberLength, Span<byte> packetNumberSpan) {
        int start = packetNumberSpan.Length - packetNumberLength;

        for(int i = start; i < packetNumberSpan.Length; i++)
            packetNumberSpan[i] = (byte)(packetNumberSpan[i] ^ mask[i - start + 1]);

        return BinaryPrimitives.ReadUInt32BigEndian(packetNumberSpan);
    }
}
