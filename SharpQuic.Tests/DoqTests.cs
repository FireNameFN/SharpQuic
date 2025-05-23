using System;
using System.Buffers.Binary;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using DNS.Protocol;
using NUnit.Framework;

namespace SharpQuic.Tests;

[TestFixture]
public class DoqTests {
    [Test]
    public async Task ConnectToAdGuardDoqTestAsync() {
        CancellationTokenSource source = new(20000);

        IPHostEntry entry = await Dns.GetHostEntryAsync("dns.adguard-dns.com");
        
        QuicConnection connection = await QuicConnection.ConnectAsync(new() {
            RemotePoint = new(entry.AddressList[0], 853),
            Protocols = ["doq"],
            CancellationToken = source.Token,
            DebugInputPacketLoss = 0.25,
            DebugOutputPacketLoss = 0.25
        });

        string[] addresses = [
            "dns.adguard-dns.com",
            "google.com",
            "youtube.com",
            "twitch.tv"
        ];

        foreach(string address in addresses) {
            QuicStream stream = await connection.OpenBidirectionalStream();

            Request request = new() {
                Id = 0,
                RecursionDesired = true,
                Questions = {
                    new(new(address))
                }
            };

            Console.WriteLine(request);

            byte[] data = request.ToArray();

            byte[] lengthArray = new byte[sizeof(ushort)];

            BinaryPrimitives.WriteUInt16BigEndian(lengthArray, (ushort)data.Length);

            data = [..lengthArray, ..data];

            await stream.WriteAsync(data, true);

            await stream.FlushAsync();

            await stream.ReadAsync(lengthArray);

            int length = BinaryPrimitives.ReadUInt16BigEndian(lengthArray);

            data = new byte[length];

            await stream.ReadAsync(data);

            Response response = Response.FromArray(data);

            Console.WriteLine(response);
        }
    }

    [Test, Explicit]
    public async Task ConnectToLocalDoqTestAsync() {
        QuicConnection connection = await QuicConnection.ConnectAsync(new() {
            RemotePoint = IPEndPoint.Parse("127.0.0.1:853"),
            Protocols = ["doq"]
        });

        QuicStream stream = await connection.OpenBidirectionalStream();

        Request request = new();

        request.RecursionDesired = true;
        request.Id = 0;
        request.Questions.Add(new(new("google.com")));

        byte[] data = request.ToArray();

        byte[] length = new byte[sizeof(ushort)];

        BinaryPrimitives.WriteUInt16BigEndian(length, (ushort)data.Length);

        data = [..length, ..data];

        await stream.WriteAsync(data, true);

        await Task.Delay(200);

        //await stream.WriteAsync(request.ToArray());

        await Task.Delay(1500);

        //await Task.Delay(5000);
    }

    /*class Message() {
        public ushort Id { get; set; }

        public bool IsResponse { get; set; }

        public byte OpCode { get; set; }

        public byte RCode { get; set; }

        public ushort QdCount { get; set; }

        public ushort AnCount { get; set; }

        public ushort NsCount { get; set; }

        public ushort ArCount { get; set; }

        public byte[] Encode() {

        }

        public Message Decode(byte[] decode) {

        }
    }*/
}
