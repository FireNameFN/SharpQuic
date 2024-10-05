namespace SharpQuic;

public struct QuicTransportParameters() {
    public int MaxIdleTimeout { get; set; } = 0;

    public int MaxUdpPayloadSize { get; set; } = 65527;

    public int InitialMaxData { get; set; } = 0;

    public byte[] InitialSourceConnectionId { get; set; } = [];
}
