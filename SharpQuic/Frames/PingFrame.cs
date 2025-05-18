namespace SharpQuic.Frames;

public sealed class PingFrame : Frame {
    public PingFrame() : base(FrameType.Ping) { }
}
