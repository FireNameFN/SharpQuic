namespace SharpQuic.Frames;

public abstract class Frame(FrameType type) {
    public FrameType Type { get; } = type;
}
