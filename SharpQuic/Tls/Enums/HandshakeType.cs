namespace SharpQuic.Tls.Enums;

public enum HandshakeType : byte {
    ClientHello = 1,
    ServerHello = 2,
    EncryptedExtensions = 8,
    Certificate = 11,
    CertificateVerify = 15,
    Finished = 20
}
