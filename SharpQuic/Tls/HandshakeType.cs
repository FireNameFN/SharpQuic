namespace SharpQuic.Tls;

public enum HandshakeType : byte {
    ClientHello = 1,
    ServerHello = 2,
    Certificate = 11,
    CertificateVerify = 15,
    Finished = 20
}
