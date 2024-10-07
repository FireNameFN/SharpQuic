using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace SharpQuic;

public readonly struct QuicConfiguration() {
    public IPEndPoint Point { get; init; }

    public string[] Protocols { get; init; }

    public X509Certificate2[] CertificateChain { get; init; }

    public QuicTransportParameters Parameters { get; init; } = new();
}
