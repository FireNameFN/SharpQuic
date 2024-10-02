using System.IO;

namespace SharpQuic.Tls.Messages;

public interface IMessage {
    HandshakeType Type { get; }

    void Encode(Stream stream);
}
