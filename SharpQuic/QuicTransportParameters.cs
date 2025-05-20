namespace SharpQuic;

public class QuicTransportParameters() {
    public byte[] OriginalDestinationConnectionId { get; set; }

    public byte[] InitialSourceConnectionId { get; set; }

    public ulong InitialMaxData { get; set; } = 1 << 20;

    public ulong InitialMaxStreamDataBidiLocal { get; set; } = 1 << 20;

    public ulong InitialMaxStreamDataBidiRemote { get; set; } = 1 << 20;

    public ulong InitialMaxStreamDataUni { get; set; } = 1 << 20;

    public ulong InitialMaxStreamsBidi { get; set; } = 10;

    public ulong InitialMaxStreamsUni { get; set; } = 10;

    public int AckDelayExponent { get; set; } = 3;

    public int MaxAckDelay { get; set; } = 25;
}
