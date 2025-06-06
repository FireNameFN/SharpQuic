using System;
using System.Buffers.Binary;
using System.Net;
using System.Threading.Tasks;
using DNS.Protocol;
using Xunit;

namespace SharpQuic.Tests;

public class DoqTests {
    [Fact]
    public async Task ConnectToAdGuardDoqTestAsync() {
        IPHostEntry entry = await Dns.GetHostEntryAsync("dns.adguard-dns.com", TestContext.Current.CancellationToken);
        
        QuicConnection connection = await QuicConnection.ConnectAsync(new() {
            RemotePoint = new(entry.AddressList[0], 853),
            Protocols = ["doq"],
            DebugInputPacketLoss = 0.25,
            DebugOutputPacketLoss = 0.25,
            DebugLogging = true
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
}
