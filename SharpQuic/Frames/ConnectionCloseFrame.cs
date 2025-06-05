namespace SharpQuic.Frames;

public sealed class ConnectionCloseFrame : Frame {
    public ulong ErrorCode { get; set; }

    public FrameType FrameType { get; set; }

    public string ReasonPhrase { get; set; }

    public ConnectionCloseFrame() : base(FrameType.ConnectionClose) { }
}
