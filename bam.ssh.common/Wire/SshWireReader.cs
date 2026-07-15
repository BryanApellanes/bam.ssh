using System.Buffers.Binary;
using System.Text;

namespace Bam.Ssh;

/// <summary>
/// Decodes RFC 4251 §5 primitive data types from a contiguous buffer with strict validation:
/// every read is bounds-checked, length prefixes are checked against the remaining bytes before
/// any slice is taken, and violations throw <see cref="SshWireFormatException"/> rather than
/// over-reading. A stack-only ref struct — decoding allocates only where the target type demands
/// it (strings); binary fields are returned as slices of the source buffer.
/// </summary>
public ref struct SshWireReader
{
    private readonly ReadOnlySpan<byte> _buffer;
    private int _position;

    /// <summary>
    /// Initializes a reader over the given buffer.
    /// </summary>
    /// <param name="buffer">The bytes to decode.</param>
    public SshWireReader(ReadOnlySpan<byte> buffer)
    {
        _buffer = buffer;
        _position = 0;
    }

    /// <summary>
    /// Gets the number of bytes not yet consumed.
    /// </summary>
    public readonly int Remaining => _buffer.Length - _position;

    /// <summary>
    /// Gets the current read position from the start of the buffer.
    /// </summary>
    public readonly int Position => _position;

    /// <summary>
    /// Reads a single byte.
    /// </summary>
    /// <returns>The byte read.</returns>
    /// <exception cref="SshWireFormatException">The buffer is exhausted.</exception>
    public byte ReadByte()
    {
        ReadOnlySpan<byte> slice = Take(1);
        return slice[0];
    }

    /// <summary>
    /// Reads an RFC 4251 boolean. Per the RFC, zero is false and any non-zero value must be
    /// interpreted as true.
    /// </summary>
    /// <returns>The boolean read.</returns>
    /// <exception cref="SshWireFormatException">The buffer is exhausted.</exception>
    public bool ReadBoolean()
    {
        return ReadByte() != 0;
    }

    /// <summary>
    /// Reads an unsigned 32-bit integer in network byte order.
    /// </summary>
    /// <returns>The value read.</returns>
    /// <exception cref="SshWireFormatException">Fewer than four bytes remain.</exception>
    public uint ReadUInt32()
    {
        ReadOnlySpan<byte> slice = Take(4);
        return BinaryPrimitives.ReadUInt32BigEndian(slice);
    }

    /// <summary>
    /// Reads an unsigned 64-bit integer in network byte order.
    /// </summary>
    /// <returns>The value read.</returns>
    /// <exception cref="SshWireFormatException">Fewer than eight bytes remain.</exception>
    public ulong ReadUInt64()
    {
        ReadOnlySpan<byte> slice = Take(8);
        return BinaryPrimitives.ReadUInt64BigEndian(slice);
    }

    /// <summary>
    /// Reads an RFC 4251 string body as a slice of the source buffer (no copy).
    /// The uint32 length prefix is validated against the remaining bytes before slicing.
    /// </summary>
    /// <returns>The string body bytes.</returns>
    /// <exception cref="SshWireFormatException">The length prefix exceeds the remaining bytes.</exception>
    public ReadOnlySpan<byte> ReadString()
    {
        uint length = ReadUInt32();
        if (length > (uint)Remaining)
        {
            throw new SshWireFormatException($"String length {length} exceeds the {Remaining} bytes remaining in the buffer.");
        }
        return Take((int)length);
    }

    /// <summary>
    /// Reads an RFC 4251 string and decodes it as UTF-8 text — the encoding RFC 4251 prescribes
    /// for human-readable strings.
    /// </summary>
    /// <returns>The decoded text.</returns>
    /// <exception cref="SshWireFormatException">The length prefix exceeds the remaining bytes.</exception>
    public string ReadText()
    {
        ReadOnlySpan<byte> body = ReadString();
        return Encoding.UTF8.GetString(body);
    }

    /// <summary>
    /// Reads and validates an RFC 4251 name-list.
    /// </summary>
    /// <returns>The parsed name-list.</returns>
    /// <exception cref="SshWireFormatException">The body is not a valid comma-separated ASCII name-list.</exception>
    public SshNameList ReadNameList()
    {
        ReadOnlySpan<byte> body = ReadString();
        return SshNameList.Parse(body);
    }

    /// <summary>
    /// Reads an RFC 4251 mpint and returns its raw two's-complement body after validating
    /// minimal encoding. Use <see cref="SshMpint.ToUnsignedMagnitude"/> to obtain the unsigned
    /// magnitude protocol fields require.
    /// </summary>
    /// <returns>The minimally-encoded two's-complement body (empty for zero).</returns>
    /// <exception cref="SshWireFormatException">The body is not minimally encoded.</exception>
    public ReadOnlySpan<byte> ReadMultiPrecisionInteger()
    {
        ReadOnlySpan<byte> body = ReadString();
        SshMpint.ValidateMinimalEncoding(body);
        return body;
    }

    /// <summary>
    /// Reads an RFC 4251 mpint as an unsigned big-endian magnitude: validates minimal encoding,
    /// rejects negative values, and strips the sign byte when present.
    /// </summary>
    /// <returns>The unsigned magnitude (empty for zero).</returns>
    /// <exception cref="SshWireFormatException">The value is negative or not minimally encoded.</exception>
    public ReadOnlySpan<byte> ReadMultiPrecisionIntegerMagnitude()
    {
        ReadOnlySpan<byte> body = ReadMultiPrecisionInteger();
        return SshMpint.ToUnsignedMagnitude(body);
    }

    /// <summary>
    /// Reads a fixed number of bytes verbatim as a slice of the source buffer.
    /// </summary>
    /// <param name="count">The number of bytes to read.</param>
    /// <returns>The bytes read.</returns>
    /// <exception cref="SshWireFormatException">Fewer than <paramref name="count"/> bytes remain.</exception>
    public ReadOnlySpan<byte> ReadRaw(int count)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        return Take(count);
    }

    private ReadOnlySpan<byte> Take(int count)
    {
        if (count > Remaining)
        {
            throw new SshWireFormatException($"Attempted to read {count} bytes with only {Remaining} remaining.");
        }
        ReadOnlySpan<byte> slice = _buffer.Slice(_position, count);
        _position += count;
        return slice;
    }
}
