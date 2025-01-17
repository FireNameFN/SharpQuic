namespace SharpQuic.Frames;

public sealed class MaxStreamDataFrame : Frame {
    public ulong Id { get; set; }

    public ulong MaxStreamData { get; set; }

    public MaxStreamDataFrame() : base(FrameType.Stream) { }
}
