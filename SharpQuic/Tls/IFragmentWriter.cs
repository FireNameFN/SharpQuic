using System;

namespace SharpQuic.Tls;

public interface IFragmentWriter {
    void WriteFragment(ReadOnlySpan<byte> fragment);
}
