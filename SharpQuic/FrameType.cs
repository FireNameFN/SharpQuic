namespace SharpQuic;

public enum FrameType : ulong {
    Ack = 0x02,
    Crypto = 0x06,
    NewToken = 0x07,
    Stream = 0x08,
    StreamMax = 0x0F,
    StreamOffset = 0b1100,
    StreamLength = 0b1010,
    StreamFin = 0b1001,
    MaxStreamData = 0x11,
    MaxStreams = 0x12,
    NewConnectionId = 0x18,
    ConnectionClose = 0x1C,
    ConnectionClose2 = 0x1D,
    HandshakeDone = 0x1E
}
