using System.IO;

namespace SharpQuic.Tls.Extensions;

public static class QuicTransportParametersExtension {
    public static void Encode(Stream stream, QuicTransportParameters parameters) {
        Serializer.WriteUInt16(stream, (ushort)ExtensionType.QuicTransportParameters);

        MemoryStream parametersStream = new();

        if(parameters.OriginalDestinationConnectionId is not null) {
            Serializer.WriteVariableLength(parametersStream, 0x00);
            Serializer.WriteVariableLength(parametersStream, (ulong)parameters.OriginalDestinationConnectionId.Length);
            parametersStream.Write(parameters.OriginalDestinationConnectionId);
        }

        Serializer.WriteVariableLength(parametersStream, 0x0f);
        Serializer.WriteVariableLength(parametersStream, (ulong)parameters.InitialSourceConnectionId.Length);
        parametersStream.Write(parameters.InitialSourceConnectionId);

        Serializer.WriteUInt16(stream, (ushort)parametersStream.Length);

        parametersStream.Position = 0;

        parametersStream.CopyTo(stream);
    }
}
