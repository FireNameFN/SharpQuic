namespace SharpQuic.Frames;

public sealed class HandshakeDoneFrame : Frame {
    public HandshakeDoneFrame() : base(FrameType.HandshakeDone) { }
}
