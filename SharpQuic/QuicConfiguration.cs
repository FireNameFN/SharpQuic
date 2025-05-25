using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

namespace SharpQuic;

public readonly struct QuicConfiguration() {
    public IPEndPoint LocalPoint { get; init; }

    public IPEndPoint RemotePoint { get; init; }

    public string[] Protocols { get; init; }

    public X509Certificate2[] CertificateChain { get; init; }

    public bool ClientAuthentication { get; init; }

    public X509ChainPolicy ChainPolicy { get; init; }

    public QuicTransportParameters Parameters { get; init; } = new();

    public CancellationToken CancellationToken { get; init; }

    public bool DebugLogging { get; init; }

    public double DebugInputPacketLoss { get; init; }

    public double DebugOutputPacketLoss { get; init; }
}
