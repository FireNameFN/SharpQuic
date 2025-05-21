namespace SharpQuic.Frames;

public sealed class MaxStreamsFrame : Frame {
    public bool Bidirectional { get; set; }

    public ulong MaxStreams { get; set; }

    public MaxStreamsFrame() : base(FrameType.MaxStreamsBidirectional) { }
}
