namespace SharpQuic.Tls.Enums;

public enum CipherSuite : ushort {
    Aes128GcmSHA256 = 0x1301,
    Aes256GcmSHA384 = 0x1302,
    ChaCha20Poly1305Sha256 = 0x1303
}
