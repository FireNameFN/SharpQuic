using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace SharpQuic;

internal static class QuicPort {
    static readonly Dictionary<IPEndPoint, Socket> sockets = [];

    static readonly List<QuicConnection> connections = [];

    static readonly List<QuicConnection> listeners = [];

    static readonly SemaphoreSlim semaphore = new(1, 1);

    public static Socket CreateSocket() {
        return new(SocketType.Dgram, ProtocolType.Udp);
    }

    public static async Task SubscribeAsync(QuicConnection connection, IPEndPoint local, bool listener) {
        await semaphore.WaitAsync();

        Socket socket = GetSocket(local);

        connection.socket = socket;

        if(listener)
            listeners.Add(connection);

        connections.Add(connection);

        semaphore.Release();

        Socket GetSocket(IPEndPoint local) {
            ref Socket socket = ref CollectionsMarshal.GetValueRefOrAddDefault(sockets, local, out bool exists);

            Console.WriteLine("Get Socket");

            if(exists)
                return socket;

            Console.WriteLine("Creating new");

            socket = CreateSocket();

            socket.Bind(local);

            Socket valSocket = socket;

            Task.Run(() => Runner(valSocket));

            return socket;
        }
    }

    public static async Task SubscribeAsync(QuicConnection connection, IPEndPoint local, Socket socket) {
        await semaphore.WaitAsync();

        sockets[local] = socket;

        connections.Add(connection);

        semaphore.Release();

        _ = Task.Run(() => Runner(socket));
    }

    public static async Task UnsubscribeAsync(QuicConnection connection) {
        await semaphore.WaitAsync();

        connections.Remove(connection);

        listeners.Remove(connection);

        semaphore.Release();
    }

    static async Task Runner(Socket socket) {
        byte[] data = new byte[1500];

        IPEndPoint point = new(IPAddress.Any, 0);

        //long time = Stopwatch.GetTimestamp();

        while(true) {
            try {
                //Console.WriteLine($"Receiving {socket.LocalEndPoint}");

                SocketReceiveFromResult result = await socket.ReceiveFromAsync(data, point);

                //Console.WriteLine($"Time: {(Stopwatch.GetTimestamp() - time) * 1000 / Stopwatch.Frequency}");

                //Console.WriteLine(result.RemoteEndPoint);

                //Console.WriteLine(result.ReceivedBytes);

                Memory<byte> id;

                if((data[0] & 0b10000000) != 0)
                    id = data.AsMemory().Slice(6, 20);
                else
                    id = data.AsMemory().Slice(1, 20);

                //Console.WriteLine($"Waiting by {socket.LocalEndPoint} {(Stopwatch.GetTimestamp() - time) * 1000 / Stopwatch.Frequency}");

                await semaphore.WaitAsync();

                bool received = false;

                foreach(QuicConnection connection in connections) {
                    if(!connection.sourceConnectionId.AsSpan().SequenceEqual(id.Span[..connection.sourceConnectionId.Length]))
                        continue;

                    //Console.WriteLine($"Received {result.ReceivedBytes} {(Stopwatch.GetTimestamp() - time) * 1000 / Stopwatch.Frequency}");

                    await connection.ReceiveAsync((IPEndPoint)result.RemoteEndPoint, data, result.ReceivedBytes);

                    received = true;

                    break;
                }

                if(!received && listeners.Count > 0) {
                    await listeners[0].ReceiveAsync((IPEndPoint)result.RemoteEndPoint, data, result.ReceivedBytes);

                    listeners.RemoveAt(0);
                }

                semaphore.Release();

                //Console.WriteLine($"Releasing by {socket.LocalEndPoint} {(Stopwatch.GetTimestamp() - time) * 1000 / Stopwatch.Frequency}");
            } catch(Exception e) {
                Console.WriteLine(e);
            }
        }
    }
}
