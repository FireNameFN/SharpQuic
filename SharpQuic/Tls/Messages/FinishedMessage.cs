using System;
using System.IO;
using System.Security.Cryptography;
using SharpQuic.Tls.Enums;

namespace SharpQuic.Tls.Messages;

public sealed class FinishedMessage : IMessage {
    public HandshakeType Type { get; } = HandshakeType.Finished;

    public byte[] VerifyData { get; set; }

    public static FinishedMessage Create(byte[] messages, byte[] handshakeSecret) {
        FinishedMessage message = new() {
            VerifyData = new byte[32]
        };

        CreateVerifyData(messages, handshakeSecret, message.VerifyData);

        return message;
    }

    public void Encode(Stream stream) {
        stream.Write(VerifyData);
    }

    public static FinishedMessage Decode(Stream stream) {
        FinishedMessage message = new() {
            VerifyData = new byte[32]
        };

        stream.ReadExactly(message.VerifyData);

        return message;
    }

    public bool Verify(byte[] messages, byte[] handshakeSecret) {
        Span<byte> data = stackalloc byte[32];

        CreateVerifyData(messages, handshakeSecret, data);

        return data.SequenceEqual(VerifyData);
    }

    static void CreateVerifyData(byte[] messages, byte[] handshakeSecret, Span<byte> data) {
        Span<byte> key = stackalloc byte[32];

        HKDFExtensions.ExpandLabel(handshakeSecret, "finished", key);

        HMACSHA256.HashData(key, messages, data);
    }
}
