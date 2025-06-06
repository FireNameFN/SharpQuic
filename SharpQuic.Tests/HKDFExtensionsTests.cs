using System;
using System.Security.Cryptography;
using SharpQuic.Tls;
using Xunit;

namespace SharpQuic.Tests;

public class HKDFExtensionsTests {
    [Fact]
    public void ExpandLabelTest() {
        Span<byte> initialSalt = stackalloc byte[20];

        Converter.HexToBytes("38762cf7f55934b34d179ae6a4c80cadccbb7f0a", initialSalt);

        Span<byte> connectionId = stackalloc byte[8];

        Converter.HexToBytes("8394c8f03e515708", connectionId);

        Span<byte> initialSecret = stackalloc byte[32];

        HKDF.Extract(HashAlgorithmName.SHA256, connectionId, initialSalt, initialSecret);

        Span<byte> initialSecretTest = stackalloc byte[32];

        Converter.HexToBytes("7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44", initialSecretTest);

        Assert.True(initialSecret.SequenceEqual(initialSecretTest));

        Span<byte> clientInitialSecret = stackalloc byte[32];

        HKDFExtensions.ExpandLabel(HashAlgorithmName.SHA256, initialSecret, "client in", clientInitialSecret);

        Span<byte> clientInitialSecretTest = stackalloc byte[32];

        Converter.HexToBytes("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea", clientInitialSecretTest);

        Assert.True(clientInitialSecret.SequenceEqual(clientInitialSecretTest));

        Span<byte> key = stackalloc byte[16];

        HKDFExtensions.ExpandLabel(HashAlgorithmName.SHA256, clientInitialSecret, "quic key", key);

        Span<byte> keyTest = stackalloc byte[16];

        Converter.HexToBytes("1f369613dd76d5467730efcbe3b1a22d", keyTest);

        Assert.True(key.SequenceEqual(keyTest));
    }
}
