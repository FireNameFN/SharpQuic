namespace SharpQuic;

public readonly record struct Frame(FrameType Type, byte[] Data);
