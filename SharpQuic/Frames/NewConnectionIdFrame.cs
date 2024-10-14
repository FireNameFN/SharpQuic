namespace SharpQuic.Frames;

public sealed class NewConnectionIdFrame : Frame {
    public NewConnectionIdFrame() : base(FrameType.NewConnectionId) { }
}
