namespace SharpQuic.Frames;

public sealed class CryptoFrame : Frame {
    public ulong Offset { get; set; }

    public ulong Length { get; set; }

    public byte[] Data { get; set; }

    public CryptoFrame() : base(FrameType.Crypto) { }
}
