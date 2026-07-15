using System.Buffers;
using System.Buffers.Binary;

namespace Bam.Ssh;

/// <summary>
/// Frames payloads into RFC 4253 §6 binary packets: computes the padding length that brings the
/// packet to a multiple of the cipher's alignment (per the supplied <see cref="SshPacketGeometry"/>),
/// writes the packet_length and padding_length fields, the payload, and cryptographically random
/// padding. Stateless and thread-safe — sequence numbers and encryption are the transport's
/// responsibility, applied around this encoder.
/// </summary>
public sealed class SshPacketEncoder
{
    private readonly ISshRandom _random;

    /// <summary>
    /// Initializes an encoder that fills padding from the given randomness source.
    /// </summary>
    /// <param name="random">The randomness source for padding bytes.</param>
    /// <exception cref="ArgumentNullException">The randomness source is null.</exception>
    public SshPacketEncoder(ISshRandom random)
    {
        ArgumentNullException.ThrowIfNull(random);
        _random = random;
    }

    /// <summary>
    /// Initializes an encoder using <see cref="SecureSshRandom.Instance"/>.
    /// </summary>
    public SshPacketEncoder() : this(SecureSshRandom.Instance)
    {
    }

    /// <summary>
    /// Computes the padding length RFC 4253 §6 requires for a payload under the given geometry:
    /// the smallest value of at least <see cref="SshPacketGeometry.MinimumPaddingLength"/> that
    /// brings the aligned region to a multiple of the block size.
    /// </summary>
    /// <param name="payloadLength">The payload byte count.</param>
    /// <param name="geometry">The cipher framing parameters.</param>
    /// <returns>The padding length (always between 4 and block size + 3).</returns>
    /// <exception cref="ArgumentOutOfRangeException">The payload length is negative.</exception>
    public static int GetPaddingLength(int payloadLength, in SshPacketGeometry geometry)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(payloadLength);
        int blockSize = geometry.BlockSize;
        int alignedBytes = (geometry.LengthIsEncrypted ? 4 : 0) + 1 + payloadLength;
        int padding = blockSize - (alignedBytes % blockSize);
        if (padding < SshPacketGeometry.MinimumPaddingLength)
        {
            padding += blockSize;
        }
        return padding;
    }

    /// <summary>
    /// Computes the total encoded frame size (length field + padding_length field + payload +
    /// padding, excluding any MAC) for buffer sizing.
    /// </summary>
    /// <param name="payloadLength">The payload byte count.</param>
    /// <param name="geometry">The cipher framing parameters.</param>
    /// <returns>The total frame length in bytes.</returns>
    public static int GetEncodedLength(int payloadLength, in SshPacketGeometry geometry)
    {
        return checked(4 + 1 + payloadLength + GetPaddingLength(payloadLength, geometry));
    }

    /// <summary>
    /// Encodes one packet: writes the uint32 packet_length, the padding_length byte, the payload
    /// verbatim, and random padding to the output. The caller applies encryption, MAC, and
    /// sequence-number bookkeeping around the encoded bytes.
    /// </summary>
    /// <param name="payload">The packet payload (message number + message fields).</param>
    /// <param name="output">The destination for the encoded frame.</param>
    /// <param name="geometry">The cipher framing parameters.</param>
    /// <exception cref="ArgumentNullException">The output is null.</exception>
    public void Encode(ReadOnlySpan<byte> payload, IBufferWriter<byte> output, in SshPacketGeometry geometry)
    {
        ArgumentNullException.ThrowIfNull(output);
        int paddingLength = GetPaddingLength(payload.Length, in geometry);
        uint packetLength = checked((uint)(1 + payload.Length + paddingLength));

        Span<byte> header = output.GetSpan(5);
        BinaryPrimitives.WriteUInt32BigEndian(header, packetLength);
        header[4] = (byte)paddingLength;
        output.Advance(5);

        if (!payload.IsEmpty)
        {
            Span<byte> body = output.GetSpan(payload.Length);
            payload.CopyTo(body);
            output.Advance(payload.Length);
        }

        Span<byte> padding = output.GetSpan(paddingLength).Slice(0, paddingLength);
        _random.Fill(padding);
        output.Advance(paddingLength);
    }
}
