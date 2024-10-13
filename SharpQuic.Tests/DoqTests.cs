using System;
using System.Buffers.Binary;
using System.Net;
using System.Threading.Tasks;
using DNS.Protocol;
using NUnit.Framework;

namespace SharpQuic.Tests;

[TestFixture]
public class DoqTests {
    [Test, Explicit]
    public async Task Test() {
        IPHostEntry entry = await Dns.GetHostEntryAsync("dns.adguard-dns.com");
        
        QuicConnection connection = await QuicConnection.ConnectAsync(new() {
            Point = new(entry.AddressList[0], 853),
            Protocols = ["doq"]
        });

        QuicStream stream = connection.OpenBidirectionalStream();

        Request request = new();

        request.RecursionDesired = true;
        request.Id = 0;
        request.Questions.Add(new(new("dns.adguard-dns.com")));

        Console.WriteLine(request);

        byte[] data = request.ToArray();

        byte[] length = new byte[sizeof(ushort)];

        BinaryPrimitives.WriteUInt16BigEndian(length, (ushort)data.Length);

        await stream.WriteAsync([..length, ..data], true);

        await Task.Delay(200);

        data = await connection.data.Task;

        data = data[2..];

        Response response = Response.FromArray(data);

        Console.WriteLine(response);

        //await stream.WriteAsync(request.ToArray());

        await Task.Delay(1500);

        //await Task.Delay(5000);
    }

    [Test, Explicit]
    public async Task Test2() {
        QuicConnection connection = await QuicConnection.ConnectAsync(new() {
            Point = IPEndPoint.Parse("127.0.0.1:853"),
            Protocols = ["doq"]
        });

        QuicStream stream = connection.OpenBidirectionalStream();

        Request request = new();

        request.RecursionDesired = true;
        request.Id = 0;
        request.Questions.Add(new(new("google.com")));

        byte[] data = request.ToArray();

        byte[] length = new byte[sizeof(ushort)];

        BinaryPrimitives.WriteUInt16BigEndian(length, (ushort)data.Length);

        await stream.WriteAsync([..length, ..data], true);

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
