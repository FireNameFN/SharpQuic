using System;
using System.IO;
using System.Security.Cryptography;

namespace SharpQuic.Tls.Messages;

public sealed class FinishedMessage : IMessage {
    public HandshakeType Type { get; } = HandshakeType.Finished;

    public byte[] Messages { get; set; }

    public byte[] ServerHandshakeSecret { get; set; }

    public void Encode(Stream stream) {
        Span<byte> key = stackalloc byte[32];

        HKDFExtensions.ExpandLabel(ServerHandshakeSecret, "finished", key);

        Span<byte> data = stackalloc byte[32];

        HMACSHA256.HashData(key, Messages, data);
    }

    //public static FinishedMessage Decode(Stream stream) {
        
    //}
}
