namespace SharpQuic.Tls.Enums;

public enum SignatureScheme : ushort {
    RSAPkcs1SHA256 = 0x0401,
    ECDSASecp256r1SHA256 = 0x0403,
    RSAPssRsaeSHA256 = 0x0804
}
