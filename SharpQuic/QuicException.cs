using System;

namespace SharpQuic;

public sealed class QuicException : Exception {
    public TransportErrorCode Code { get; }

    public QuicException() : base() { }

    public QuicException(TransportErrorCode code) : base($"Error of type {code}") {
        Code = code;
    }

    public enum TransportErrorCode : ushort {
        NoError = 0x00,
        ProtocolViolation = 0x0A
    }
}
