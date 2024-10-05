namespace SharpQuic.Tls.Extensions;

public enum ExtensionType : ushort {
    SupportedGroups = 10,
    SignatureAlgorithms = 13,
    ApplicationLayerProtocolNegotiation = 16,
    SupportedVersions = 43,
    KeyShare = 51,
    QuicTransportParameters = 57
}
