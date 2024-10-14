namespace SharpQuic.Frames;

public sealed class AckFrame : Frame {
    public AckFrame() : base(FrameType.Ack) { }
}
