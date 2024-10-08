namespace SharpQuic;

public enum PacketType : byte {
    LongHeader = 0b10000000,
    Initial = 0b11000000,
    Handshake = 0b11100000,
    Retry = 0b11110000,
    OneRtt = 0b01000000,
    OneRttSpin = 0b01100000
}
