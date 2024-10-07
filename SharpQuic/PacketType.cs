namespace SharpQuic;

public enum PacketType : byte {
    Initial = 0b11000000,
    Handshake = 0b11100000,
    Retry = 0b11110000
}
