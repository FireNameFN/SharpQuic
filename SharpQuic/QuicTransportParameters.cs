namespace SharpQuic;

public class QuicTransportParameters() {
    //public int MaxIdleTimeout { get; set; } = 0;

    //public int MaxUdpPayloadSize { get; set; } = 65527;

    //public int InitialMaxData { get; set; } = 0;

    public byte[] InitialSourceConnectionId { get; set; }

    public byte[] OriginalDestinationConnectionId { get; set; }

    public ulong InitialMaxData { get; set; } = 1 << 10;

    public ulong InitialMaxStreamDataBidiLocal { get; set; } = 1 << 10;

    public ulong InitialMaxStreamDataBidiRemote { get; set; } = 1 << 10;

    public ulong InitialMaxStreamDataUni { get; set; } = 1 << 10;

    public ulong InitialMaxStreamsBidi { get; set; } = 10;

    public ulong InitialMaxStreamsUni { get; set; } = 10;
}
