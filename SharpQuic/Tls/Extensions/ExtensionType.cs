namespace SharpQuic.Tls.Extensions;

public enum ExtensionType : ushort {
    SupportedGroups = 10,
    SupportedVersions = 43,
    KeyShare = 51
}
