using System.Net.Sockets;
using System.Threading.Tasks;
using SharpQuic.Tls;

namespace SharpQuic;

public sealed class QuicConnection {
    readonly UdpClient client;

    readonly TlsClient tlsClient = new();

    QuicConnection(UdpClient client) {
        this.client = client;

        //client.
    }

    //public static async Task<QuicConnection> ConnectAsync() {
        
    //}
}
