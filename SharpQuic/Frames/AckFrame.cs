namespace SharpQuic.Frames;

public sealed class AckFrame : Frame {
    public uint LargestAcknowledged { get; set; }

    public int AckDelay { get; set; }

    public uint FirstAckRange { get; set; }

    public AckRange[] AckRanges { get; set; }

    public AckFrame() : base(FrameType.Ack) { }

    public readonly record struct AckRange() {
        public uint Gap { get; init; }

        public uint AckRangeLength { get; init; }
    }
}
