namespace SharpQuic.Tls.Extensions;

public enum ExtensionType : ushort {
    SupportedGroups = 10,
    SignatureAlgorithms = 13,
    SupportedVersions = 43,
    KeyShare = 51
}
