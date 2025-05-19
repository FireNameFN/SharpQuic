using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

namespace SharpQuic;

public readonly struct QuicConfiguration() {
    public IPEndPoint Point { get; init; }

    public string[] Protocols { get; init; }

    public X509Certificate2[] CertificateChain { get; init; }

    public X509ChainPolicy ChainPolicy { get; init; }

    public QuicTransportParameters Parameters { get; init; } = new();

    public CancellationToken CancellationToken { get; init; }

    public double DebugInputPacketLoss { get; init; }

    public double DebugOutputPacketLoss { get; init; }
}
