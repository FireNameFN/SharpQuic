using System.IO;
using SharpQuic.Tls.Enums;

namespace SharpQuic.Tls.Messages;

public interface IMessage {
    HandshakeType Type { get; }

    void Encode(Stream stream);
}
