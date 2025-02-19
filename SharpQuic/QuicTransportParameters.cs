namespace SharpQuic;

public class QuicTransportParameters() {
    public byte[] OriginalDestinationConnectionId { get; set; }

    public byte[] InitialSourceConnectionId { get; set; }

    public ulong InitialMaxData { get; set; } = 1 << 10;

    public ulong InitialMaxStreamDataBidiLocal { get; set; } = 1 << 10;

    public ulong InitialMaxStreamDataBidiRemote { get; set; } = 1 << 10;

    public ulong InitialMaxStreamDataUni { get; set; } = 1 << 10;

    public ulong InitialMaxStreamsBidi { get; set; } = 10;

    public ulong InitialMaxStreamsUni { get; set; } = 10;
}
