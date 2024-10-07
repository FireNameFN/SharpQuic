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

        Assert.That(hex.Equals("bdbbe8757494bef20de932598294ea65b5e6bf6dc5c02a960a2de2eaa9b07c929078d2caa0936231c38d1725f179d299", System.StringComparison.CurrentCultureIgnoreCase));

        byte[] messagesArray = Converter.HexToBytes("e05f64fcd082bdb0dce473adf669c2769f257a1c75a51b7887468b5e0e7a7de4f4d34555112077f16e079019d5a845bd");

        byte[] clientHandshakeSecret = new byte[48];

        HKDFExtensions.ExpandLabel(HashAlgorithmName.SHA384, hash, "c hs traffic", messagesArray, clientHandshakeSecret);

        byte[] serverHandshakeSecret = new byte[48];

        HKDFExtensions.ExpandLabel(HashAlgorithmName.SHA384, hash, "s hs traffic", messagesArray, serverHandshakeSecret);

        Assert.That(Converter.BytesToHex(clientHandshakeSecret).Equals("db89d2d6df0e84fed74a2288f8fd4d0959f790ff23946cdf4c26d85e51bebd42ae184501972f8d30c4a3e4a3693d0ef0", System.StringComparison.CurrentCultureIgnoreCase));
        Assert.That(Converter.BytesToHex(serverHandshakeSecret).Equals("23323da031634b241dd37d61032b62a4f450584d1f7f47983ba2f7cc0cdcc39a68f481f2b019f9403a3051908a5d1622", System.StringComparison.CurrentCultureIgnoreCase));
    }
}
