using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace SharpQuic;

public sealed class QuicListener : IDisposable {
    readonly Socket socket = new(SocketType.Dgram, ProtocolType.Udp);

    readonly Dictionary<EndPoint, QuicConnection> connections = [];

    readonly QuicConfiguration configuration;

    public event Action<QuicConnection> OnConnection;

    public QuicListener(QuicConfiguration configuration) {
        this.configuration = configuration;

        socket.Bind(configuration.Point);
    }

    public Task<Task> StartAsync() {
        return Task.Factory.StartNew(Runner, TaskCreationOptions.LongRunning);
    }

    async Task Runner() {
        byte[] data = new byte[1500];

        while(true) {
            Console.WriteLine("QuicListener Receiving");

            SocketReceiveFromResult result = await socket.ReceiveFromAsync(data, configuration.Point);

            if(!connections.TryGetValue(result.RemoteEndPoint, out QuicConnection connection)) {
                configuration.Parameters.InitialSourceConnectionId = RandomNumberGenerator.GetBytes(8);

                connection = new(socket, EndpointType.Server, configuration);

                connection.socket.Connect(result.RemoteEndPoint);

                connection.Point = (IPEndPoint)result.RemoteEndPoint;

                connections.Add(result.RemoteEndPoint, connection);
            }

            QuicConnection.State state = connection.state;

            await connection.ReceiveAsync(data, result.ReceivedBytes);

            if(state != QuicConnection.State.Idle && connection.state == QuicConnection.State.Idle)
                OnConnection?.Invoke(connection);
        }
    }

    public void Dispose() {
        socket.Dispose();
    }
}
