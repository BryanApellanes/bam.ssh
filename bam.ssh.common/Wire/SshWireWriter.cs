using System.Buffers;
using System.Buffers.Binary;
using System.Text;

namespace Bam.Ssh;

/// <summary>
/// Encodes RFC 4251 §5 primitive data types (byte, boolean, uint32, uint64, string, mpint,
/// name-list) into an <see cref="IBufferWriter{T}"/>. A stack-only ref struct so encoding a
/// message allocates nothing beyond what the destination writer itself manages. All multi-byte
/// integers are written big-endian (network order) as the protocol requires.
/// </summary>
public ref struct SshWireWriter
{
    private readonly IBufferWriter<byte> _output;
    private long _bytesWritten;

    /// <summary>
    /// Initializes a writer over the given destination.
    /// </summary>
    /// <param name="output">The buffer writer that receives the encoded bytes.</param>
    /// <exception cref="ArgumentNullException">The output is null.</exception>
    public SshWireWriter(IBufferWriter<byte> output)
    {
        ArgumentNullException.ThrowIfNull(output);
        _output = output;
        _bytesWritten = 0;
    }

    /// <summary>
    /// Gets the total number of bytes written through this writer so far.
    /// </summary>
    public readonly long BytesWritten => _bytesWritten;

    /// <summary>
    /// Writes a single byte.
    /// </summary>
    /// <param name="value">The byte to write.</param>
    public void WriteByte(byte value)
    {
        Span<byte> span = _output.GetSpan(1);
        span[0] = value;
        Advance(1);
    }

    /// <summary>
    /// Writes an RFC 4251 boolean: one byte, 1 for true and 0 for false.
    /// </summary>
    /// <param name="value">The value to write.</param>
    public void WriteBoolean(bool value)
    {
        WriteByte(value ? (byte)1 : (byte)0);
    }

    /// <summary>
    /// Writes an unsigned 32-bit integer in network byte order.
    /// </summary>
    /// <param name="value">The value to write.</param>
    public void WriteUInt32(uint value)
    {
        Span<byte> span = _output.GetSpan(4);
        BinaryPrimitives.WriteUInt32BigEndian(span, value);
        Advance(4);
    }

    /// <summary>
    /// Writes an unsigned 64-bit integer in network byte order.
    /// </summary>
    /// <param name="value">The value to write.</param>
    public void WriteUInt64(ulong value)
    {
        Span<byte> span = _output.GetSpan(8);
        BinaryPrimitives.WriteUInt64BigEndian(span, value);
        Advance(8);
    }

    /// <summary>
    /// Writes an RFC 4251 string: a uint32 byte count followed by the bytes verbatim.
    /// Binary-safe; the bytes are not interpreted.
    /// </summary>
    /// <param name="value">The bytes forming the string body.</param>
    public void WriteString(ReadOnlySpan<byte> value)
    {
        WriteUInt32((uint)value.Length);
        WriteRaw(value);
    }

    /// <summary>
    /// Writes an RFC 4251 string containing UTF-8 encoded text — the encoding RFC 4251
    /// prescribes for human-readable strings such as user names and error messages.
    /// </summary>
    /// <param name="value">The text to encode.</param>
    /// <exception cref="ArgumentNullException">The text is null.</exception>
    public void WriteText(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        int byteCount = Encoding.UTF8.GetByteCount(value);
        WriteUInt32((uint)byteCount);
        Span<byte> span = _output.GetSpan(byteCount);
        int written = Encoding.UTF8.GetBytes(value.AsSpan(), span);
        Advance(written);
    }

    /// <summary>
    /// Writes an RFC 4251 name-list: a uint32 byte count followed by the comma-separated
    /// ASCII names. The list validated its contents at construction, so no re-validation occurs.
    /// </summary>
    /// <param name="value">The name-list to write.</param>
    public void WriteNameList(SshNameList value)
    {
        int bodyLength = value.GetEncodedByteCount();
        WriteUInt32((uint)bodyLength);
        if (bodyLength == 0)
        {
            return;
        }
        Span<byte> span = _output.GetSpan(bodyLength);
        int position = 0;
        IReadOnlyList<string> names = value.Names;
        for (int i = 0; i < names.Count; i++)
        {
            if (i > 0)
            {
                span[position] = (byte)',';
                position++;
            }
            string name = names[i];
            int encoded = Encoding.ASCII.GetBytes(name.AsSpan(), span.Slice(position));
            position += encoded;
        }
        Advance(bodyLength);
    }

    /// <summary>
    /// Writes an RFC 4251 mpint from an unsigned big-endian magnitude, applying the minimal-form
    /// rules via <see cref="SshMpint"/>: leading zeros stripped, a 0x00 sign byte prepended when
    /// the high bit is set, and zero written as an empty string.
    /// </summary>
    /// <param name="unsignedMagnitude">The unsigned big-endian magnitude; may include leading zeros.</param>
    public void WriteMultiPrecisionInteger(ReadOnlySpan<byte> unsignedMagnitude)
    {
        ReadOnlySpan<byte> significant = SshMpint.StripLeadingZeros(unsignedMagnitude);
        if (significant.IsEmpty)
        {
            WriteUInt32(0);
            return;
        }
        bool needsSignByte = (significant[0] & 0x80) != 0;
        WriteUInt32((uint)(significant.Length + (needsSignByte ? 1 : 0)));
        if (needsSignByte)
        {
            WriteByte(0);
        }
        WriteRaw(significant);
    }

    /// <summary>
    /// Writes an RFC 4251 mpint from a raw two's-complement body without transformation,
    /// after validating it is minimally encoded. Exists for negative values (which the protocol
    /// itself never transmits) and for round-tripping the RFC's worked examples exactly.
    /// </summary>
    /// <param name="twosComplementBody">The minimally-encoded two's-complement bytes.</param>
    /// <exception cref="SshWireFormatException">The body is not minimally encoded.</exception>
    public void WriteMultiPrecisionIntegerRaw(ReadOnlySpan<byte> twosComplementBody)
    {
        SshMpint.ValidateMinimalEncoding(twosComplementBody);
        WriteString(twosComplementBody);
    }

    /// <summary>
    /// Writes bytes verbatim with no length prefix. Used for pre-encoded material
    /// (payload bodies, magnitudes) whose framing is handled elsewhere.
    /// </summary>
    /// <param name="value">The bytes to write.</param>
    public void WriteRaw(ReadOnlySpan<byte> value)
    {
        if (value.IsEmpty)
        {
            return;
        }
        Span<byte> span = _output.GetSpan(value.Length);
        value.CopyTo(span);
        Advance(value.Length);
    }

    private void Advance(int count)
    {
        _output.Advance(count);
        _bytesWritten += count;
    }
}
