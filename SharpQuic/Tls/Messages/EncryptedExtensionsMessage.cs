using System.IO;
using SharpQuic.Tls.Enums;
using SharpQuic.Tls.Extensions;

namespace SharpQuic.Tls.Messages;

public sealed class EncryptedExtensionsMessage : IMessage {
    public HandshakeType Type { get; } = HandshakeType.EncryptedExtensions;

    public string Protocol { get; set; }

    public void Encode(Stream stream) {
        MemoryStream extensionsStream = new();

        AlpnExtension.Encode(extensionsStream, [Protocol]);
        QuicTransportParametersExtension.Encode(extensionsStream, new());

        byte[] extensions = extensionsStream.ToArray();

        Serializer.WriteUInt16(stream, (ushort)extensions.Length);
        stream.Write(extensions);
    }

    public static EncryptedExtensionsMessage Decode(Stream stream) {
        EncryptedExtensionsMessage message = new();

        int length = Serializer.ReadUInt16(stream);

        long start = stream.Position;

        while(stream.Position - start < length) {
            ExtensionType type = (ExtensionType)Serializer.ReadUInt16(stream);

            int extensionLength = Serializer.ReadUInt16(stream);

            switch(type) {
                case ExtensionType.ApplicationLayerProtocolNegotiation:
                    message.Protocol = AlpnExtension.Decode(stream)[0];
                    
                    break;
                default:
                    stream.Position += extensionLength;
                    break;
            }
        }

        return message;
    }
}
