using System;
using System.Security.Cryptography;
using SharpQuic.Tls.Enums;

namespace SharpQuic.Tls;

public static class HashUtils {
    public static HashAlgorithmName GetName(CipherSuite cipherSuite) {
        return cipherSuite switch {
            CipherSuite.Aes128GcmSHA256 => HashAlgorithmName.SHA256,
            CipherSuite.Aes256GcmSHA384 => HashAlgorithmName.SHA384,
            CipherSuite.ChaCha20Poly1305Sha256 => HashAlgorithmName.SHA256,
            _ => throw new ArgumentOutOfRangeException(nameof(cipherSuite))
        };
    }

    public static int GetLength(HashAlgorithmName name) {
        if(name == HashAlgorithmName.SHA256)
            return 32;

        if(name == HashAlgorithmName.SHA384)
            return 48;
        
        throw new ArgumentOutOfRangeException(nameof(name));
    }
}
