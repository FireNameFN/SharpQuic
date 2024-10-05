using System.IO;

namespace SharpQuic.Tls.Extensions;

public static class QuicTransportParametersExtension {
    public static void Encode(Stream stream, QuicTransportParameters parameters) {
        Serializer.WriteUInt16(stream, (ushort)ExtensionType.QuicTransportParameters);

        Serializer.WriteUInt16(stream, (ushort)(2 + parameters.InitialSourceConnectionId.Length));

        Serializer.WriteVariableLength(stream, 0x0f);
        Serializer.WriteVariableLength(stream, (ulong)parameters.InitialSourceConnectionId.Length);
        stream.Write(parameters.InitialSourceConnectionId);
    }
}
