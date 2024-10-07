namespace SharpQuic;

public enum FrameType : ulong {
    Ack = 0x02,
    Crypto = 0x06,
    ConnectionClose = 0x1C,
    ConnectionClose2 = 0x1D
}
