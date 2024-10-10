namespace SharpQuic;

public sealed class Stage {
    public FrameWriter FrameWriter { get; } = new();

    public KeySet KeySet { get; init; }
}
