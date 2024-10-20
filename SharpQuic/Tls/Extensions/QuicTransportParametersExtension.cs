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

        EncodeParameter(parametersStream, 0x04, parameters.InitialMaxData);

        EncodeParameter(parametersStream, 0x05, parameters.InitialMaxStreamDataBidiLocal);

        EncodeParameter(parametersStream, 0x06, parameters.InitialMaxStreamDataBidiRemote);

        EncodeParameter(parametersStream, 0x07, parameters.InitialMaxStreamDataUni);

        EncodeParameter(parametersStream, 0x08, parameters.InitialMaxStreamsBidi);

        EncodeParameter(parametersStream, 0x09, parameters.InitialMaxStreamsUni);

        Serializer.WriteVariableLength(parametersStream, 0x0f);
        Serializer.WriteVariableLength(parametersStream, (ulong)parameters.InitialSourceConnectionId.Length);
        parametersStream.Write(parameters.InitialSourceConnectionId);

        Serializer.WriteUInt16(stream, (ushort)parametersStream.Length);

        parametersStream.Position = 0;

        parametersStream.CopyTo(stream);
    }

    static void EncodeParameter(Stream stream, ulong id, ulong value) {
        int length = Serializer.GetVariableLength(value);

        Serializer.WriteVariableLength(stream, id);
        Serializer.WriteVariableLength(stream, (ulong)length);
        Serializer.WriteVariableLength(stream, value, length);
    }
}
