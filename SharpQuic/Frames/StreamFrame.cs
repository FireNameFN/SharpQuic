namespace SharpQuic.Frames;

public sealed class StreamFrame : Frame {
    public ulong Id { get; set; }

    public bool Fin { get; set; }

    public ulong Offset { get; set; }

    public ulong Length { get; set; }

    public byte[] Data { get; set; }

    public StreamFrame() : base(FrameType.Stream) { }
}
