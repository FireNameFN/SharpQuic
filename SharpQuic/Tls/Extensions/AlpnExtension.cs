using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace SharpQuic.Tls.Extensions;

public static class AlpnExtension {
    public static void Encode(Stream stream, string[] protocols) {
        Serializer.WriteUInt16(stream, (ushort)ExtensionType.ApplicationLayerProtocolNegotiation);

        int length = protocols.Select(protocol => Encoding.ASCII.GetByteCount(protocol) + 1).Sum();

        Serializer.WriteUInt16(stream, (ushort)(length + 2));

        Serializer.WriteUInt16(stream, (ushort)length);

        foreach(string protocol in protocols) {
            byte[] protocolArray = Encoding.ASCII.GetBytes(protocol);

            Serializer.WriteByte(stream, (byte)protocolArray.Length);
            stream.Write(protocolArray);
        }
    }

    public static string[] Decode(Stream stream) {
        int length = Serializer.ReadUInt16(stream);

        long start = stream.Position;

        List<string> protocols = [];

        while(stream.Position - start < length) {
            int protocolLength = Serializer.ReadByte(stream);

            byte[] protocol = new byte[protocolLength];

            stream.ReadExactly(protocol);

            protocols.Add(Encoding.ASCII.GetString(protocol));
        }

        return [..protocols];
    }
}
