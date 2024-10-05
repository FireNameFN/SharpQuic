namespace SharpQuic;

public enum FrameType : ulong {
    Ack = 0x02,
    Crypto = 0x06
}
