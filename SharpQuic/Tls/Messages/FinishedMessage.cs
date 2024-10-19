using System;
using System.IO;
using System.Security.Cryptography;
using SharpQuic.Tls.Enums;

namespace SharpQuic.Tls.Messages;

public sealed class FinishedMessage : IMessage {
    public HandshakeType Type { get; } = HandshakeType.Finished;

    public byte[] VerifyData { get; set; }

    public static FinishedMessage Create(HashAlgorithmName name, byte[] messages, byte[] handshakeSecret) {
        FinishedMessage message = new() {
            VerifyData = new byte[HashUtils.GetLength(name)]
        };

        CreateVerifyData(name, messages, handshakeSecret, message.VerifyData);

        return message;
    }

    public void Encode(Stream stream) {
        stream.Write(VerifyData);
    }

    public static FinishedMessage Decode(HashAlgorithmName name, Stream stream) {
        FinishedMessage message = new() {
            VerifyData = new byte[HashUtils.GetLength(name)]
        };

        stream.ReadExactly(message.VerifyData);

        return message;
    }

    public bool Verify(HashAlgorithmName name, byte[] messages, byte[] handshakeSecret) {
        Span<byte> data = stackalloc byte[HashUtils.GetLength(name)];

        CreateVerifyData(name, messages, handshakeSecret, data);

        return data.SequenceEqual(VerifyData);
    }

    static void CreateVerifyData(HashAlgorithmName name, byte[] messages, byte[] handshakeSecret, Span<byte> data) {
        Span<byte> key = stackalloc byte[HashUtils.GetLength(name)];

        HKDFExtensions.ExpandLabel(name, handshakeSecret, "finished", [], key);

        if(name == HashAlgorithmName.SHA256) {
            HMACSHA256.HashData(key, messages, data);
            return;
        }

        if(name == HashAlgorithmName.SHA384) {
            HMACSHA384.HashData(key, messages, data);
            return;
        }

        throw new ArgumentOutOfRangeException(nameof(name));
    }
}
