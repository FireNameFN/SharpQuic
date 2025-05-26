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

    readonly byte[] sourceConnectionId = sourceConnectionId;

    bool initialKeysGenerated;

    void GenerateInitialKeys(byte[] clientDestinationConnectionId, KeySet keySet) {
        Span<byte> initialSecret = stackalloc byte[32];

        HKDF.Extract(HashAlgorithmName.SHA256, clientDestinationConnectionId, InitialSalt, initialSecret);

        Span<byte> clientInitialSecret = stackalloc byte[32];

        HKDFExtensions.ExpandLabel(HashAlgorithmName.SHA256, initialSecret, "client in", clientInitialSecret);

        Span<byte> serverInitialSecret = stackalloc byte[32];

        HKDFExtensions.ExpandLabel(HashAlgorithmName.SHA256, initialSecret, "server in", serverInitialSecret);
        
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

        if(!initialKeysGenerated && packet.PacketType == PacketType.Initial)
            GenerateInitialKeys(packet.DestinationConnectionId, keySet);

        Span<byte> nonce = stackalloc byte[keySet.SourceIv.Length];

        GetNonce(keySet.SourceIv, packet.PacketNumber, nonce);

        Span<byte> payload = stackalloc byte[packet.Payload.Length];

        Span<byte> tag = stackalloc byte[16];

        switch(keySet.CipherSuite) {
            case CipherSuite.Aes128GcmSHA256:
            case CipherSuite.Aes256GcmSHA384:
                using(AesGcm aesGcm = new(keySet.SourceKey, 16))
                    aesGcm.Encrypt(nonce, packet.Payload, payload, tag, packet.EncodeUnprotectedHeader());

                break;
            case CipherSuite.ChaCha20Poly1305Sha256:
                using(ChaCha20Poly1305 chacha = new(keySet.SourceKey))
                    chacha.Encrypt(nonce, packet.Payload, payload, tag, packet.EncodeUnprotectedHeader());

                break;
        }

        int packetNumberLength = packet.GetPacketNumberLength();

        Span<byte> sample = payload.Slice(4 - packetNumberLength, 16);

        Span<byte> mask = stackalloc byte[16];

        GetMask(keySet.CipherSuite, keySet.SourceHp, sample, packet.PacketType, mask);

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

        Packet packet = type switch {
            PacketType.Initial => new InitialPacket(),
            PacketType.Retry => new RetryPacket(),
            PacketType.Handshake => new HandshakePacket(),
            _ => null
        };

        if(packet is InitialPacket && initialKeySet is null)
            return null;

        if(packet is HandshakePacket && handshakeKeySet is null)
            return null;

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

            if(applicationKeySet is null)
                return null;
        }

        KeySet keySet = packet switch {
            InitialPacket => initialKeySet,
            RetryPacket => null,
            HandshakePacket => handshakeKeySet,
            OneRttPacket => applicationKeySet,
            _ => throw new NotImplementedException()
        };

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

        ulong length;

        if(packet is LongHeaderPacket)
            (length, packet.LengthLength) = Serializer.ReadVariableLength(stream);
        else
            length = (ulong)(stream.Length - stream.Position);

        Span<byte> remainder = stackalloc byte[(int)length];

        stream.ReadExactly(remainder);

        Span<byte> sample = remainder.Slice(4, 16);

        Span<byte> mask = stackalloc byte[16];

        GetMask(keySet.CipherSuite, keySet.DestinationHp, sample, type, mask);

        protectedFirstByte ^= mask[0];

        int packetNumberLength = (protectedFirstByte & 0b11) + 1;

        Span<byte> packetNumberSpan = stackalloc byte[sizeof(uint)];

        remainder[..packetNumberLength].CopyTo(packetNumberSpan[^packetNumberLength..]);

        packet.PacketNumberLength = packetNumberLength;

        packet.PacketNumber = MaskPacketNumber(mask, packetNumberLength, packetNumberSpan);

        if(packet is OneRttPacket oneRttPacket) {
            oneRttPacket.Spin = (protectedFirstByte & 0b00100000) != 0;
            oneRttPacket.KeyPhase = (protectedFirstByte & 0b00000100) != 0;
        }

        Span<byte> nonce = stackalloc byte[keySet.DestinationIv.Length];

        GetNonce(keySet.DestinationIv, packet.PacketNumber, nonce);

        Span<byte> payload = remainder[packetNumberLength..^16];

        packet.Payload = new byte[payload.Length];

        try {
            switch(keySet.CipherSuite) {
                case CipherSuite.Aes128GcmSHA256:
                case CipherSuite.Aes256GcmSHA384:
                    using(AesGcm aesGcm = new(keySet.DestinationKey, 16))
                        aesGcm.Decrypt(nonce, payload, remainder[^16..], packet.Payload, packet.EncodeUnprotectedHeader());

                    break;
                case CipherSuite.ChaCha20Poly1305Sha256:
                    using(ChaCha20Poly1305 chacha = new(keySet.SourceKey))
                        chacha.Decrypt(nonce, payload, remainder[^16..], packet.Payload, packet.EncodeUnprotectedHeader());

                    break;
            }
        } catch(AuthenticationTagMismatchException) {
            Console.WriteLine("Invalid tag.");

            return null;
        }

        return packet;
    }

    static void GetNonce(ReadOnlySpan<byte> iv, uint packetNumber, Span<byte> nonce) {
        Span<byte> packetNumberSpan = stackalloc byte[nonce.Length];

        BinaryPrimitives.WriteUInt32BigEndian(packetNumberSpan[^sizeof(uint)..], packetNumber);

        for(int i = 0; i < nonce.Length; i++)
            nonce[i] = (byte)(iv[i] ^ packetNumberSpan[i]);
    }

    static void GetMask(CipherSuite cipherSuite, byte[] hp, ReadOnlySpan<byte> sample, PacketType type, Span<byte> mask) {
        if(cipherSuite == CipherSuite.ChaCha20Poly1305Sha256) {
            using ChaCha20Poly1305 chacha = new(hp);

            chacha.Encrypt(sample[4..], [0, 0, 0, 0, 0], mask, stackalloc byte[16], sample[..3]);
        } else {
            using Aes aes = Aes.Create();

            aes.Key = hp;

            aes.EncryptEcb(sample, mask, PaddingMode.None);
        }

        mask[0] &= type.HasFlag(PacketType.LongHeader) ? (byte)0b1111 : (byte)0b11111;
    }

    static uint MaskPacketNumber(ReadOnlySpan<byte> mask, int packetNumberLength, Span<byte> packetNumberSpan) {
        int start = packetNumberSpan.Length - packetNumberLength;

        for(int i = start; i < packetNumberSpan.Length; i++)
            packetNumberSpan[i] = (byte)(packetNumberSpan[i] ^ mask[i - start + 1]);

        return BinaryPrimitives.ReadUInt32BigEndian(packetNumberSpan);
    }
}
