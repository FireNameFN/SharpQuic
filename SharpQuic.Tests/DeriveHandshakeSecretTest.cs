using System;
using System.Security.Cryptography;
using NUnit.Framework;
using SharpQuic.Tls;

namespace SharpQuic.Tests;

[TestFixture]
public class DeriveHandshakeSecretTest {
    [Test]
    public void Test() {
        byte[] zero = new byte[48];

        byte[] hash = new byte[48];

        HKDF.Extract(HashAlgorithmName.SHA384, hash, [], hash);

        HKDFExtensions.ExpandLabel(HashAlgorithmName.SHA384, hash, "derived", SHA384.HashData([]), hash);

        HKDF.Extract(HashAlgorithmName.SHA384, Converter.HexToBytes("df4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624"), hash, hash);

        string hex = Converter.BytesToHex(hash);

        Assert.That(hex.Equals("bdbbe8757494bef20de932598294ea65b5e6bf6dc5c02a960a2de2eaa9b07c929078d2caa0936231c38d1725f179d299", StringComparison.CurrentCultureIgnoreCase));

        byte[] messagesArray = Converter.HexToBytes("e05f64fcd082bdb0dce473adf669c2769f257a1c75a51b7887468b5e0e7a7de4f4d34555112077f16e079019d5a845bd");

        byte[] clientHandshakeSecret = new byte[48];

        HKDFExtensions.ExpandLabel(HashAlgorithmName.SHA384, hash, "c hs traffic", messagesArray, clientHandshakeSecret);

        byte[] serverHandshakeSecret = new byte[48];

        HKDFExtensions.ExpandLabel(HashAlgorithmName.SHA384, hash, "s hs traffic", messagesArray, serverHandshakeSecret);

        Assert.That(Converter.BytesToHex(clientHandshakeSecret).Equals("db89d2d6df0e84fed74a2288f8fd4d0959f790ff23946cdf4c26d85e51bebd42ae184501972f8d30c4a3e4a3693d0ef0", StringComparison.CurrentCultureIgnoreCase));
        Assert.That(Converter.BytesToHex(serverHandshakeSecret).Equals("23323da031634b241dd37d61032b62a4f450584d1f7f47983ba2f7cc0cdcc39a68f481f2b019f9403a3051908a5d1622", StringComparison.CurrentCultureIgnoreCase));
    }

    [Test]
    public void Test2() {
        Span<byte> hash = stackalloc byte[48];

        Converter.HexToBytes("bdbbe8757494bef20de932598294ea65b5e6bf6dc5c02a960a2de2eaa9b07c929078d2caa0936231c38d1725f179d299", hash);

        HKDFExtensions.ExpandLabel(HashAlgorithmName.SHA384, hash, "derived", SHA384.HashData([]), hash);

        Assert.That(Converter.BytesToHex(hash).Equals("be3a8cdfcd10e46d3fe5d2902568518993ae43f2fb7c5438cde4776d1bc220242041a83f388266fd07b0177bf29e9486", StringComparison.CurrentCultureIgnoreCase));

        Span<byte> messagesHash = stackalloc byte[48];

        HKDF.Extract(HashAlgorithmName.SHA384, messagesHash, hash, hash);

        Assert.That(Converter.BytesToHex(hash).Equals("2931209e1b7840e16d0d6bfd4bda1102f3a984f1162dc450f9606654f45bd55d9cb8857a8d14b59b98d7250fee55d3c3", StringComparison.CurrentCultureIgnoreCase));

        Converter.HexToBytes("fa6800169a6baac19159524fa7b9721b41be3c9db6f3f93fa5ff7e3db3ece204d2b456c51046e40ec5312c55a86126f5", messagesHash);

        byte[] clientApplicationSecret = new byte[48];

        HKDFExtensions.ExpandLabel(HashAlgorithmName.SHA384, hash, "c ap traffic", messagesHash, clientApplicationSecret);

        Assert.That(Converter.BytesToHex(clientApplicationSecret).Equals("9e47af27cb60d818a9ea7d233cb5ed4cc525fcd74614fb24b0ee59acb8e5aa7ff8d88b89792114208fec291a6fa96bad", StringComparison.CurrentCultureIgnoreCase));

        byte[] serverApplicationSecret = new byte[48];

        HKDFExtensions.ExpandLabel(HashAlgorithmName.SHA384, hash, "s ap traffic", messagesHash, serverApplicationSecret);

        byte[] clientApplicatioKey = new byte[32];

        HKDFExtensions.ExpandLabel(clientApplicationSecret, "key", clientApplicatioKey);

        //Assert.That(Converter.BytesToHex(clientApplicationSecret).Equals("db89d2d6df0e84fed74a2288f8fd4d0959f790ff23946cdf4c26d85e51bebd42ae184501972f8d30c4a3e4a3693d0ef0", StringComparison.CurrentCultureIgnoreCase));
        //Assert.That(Converter.BytesToHex(serverApplicationSecret).Equals("23323da031634b241dd37d61032b62a4f450584d1f7f47983ba2f7cc0cdcc39a68f481f2b019f9403a3051908a5d1622", StringComparison.CurrentCultureIgnoreCase));
    }
}
