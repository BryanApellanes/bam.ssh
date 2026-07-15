using System.Buffers;
using System.Buffers.Binary;

namespace Bam.Ssh;

/// <summary>
/// Incrementally recognizes RFC 4253 §6 binary packet frames in buffered input. Designed for the
/// System.IO.Pipelines pattern: feed it the currently buffered <see cref="ReadOnlySequence{T}"/>;
/// it either produces a validated <see cref="SshPacketFrame"/> and advances the sequence past the
/// frame, or reports that more bytes are needed. Every declared length is validated against
/// <see cref="SshPacketLimits"/> — with overflow-safe arithmetic — before any slice is taken,
/// so malformed or hostile input cannot cause over-reads or unbounded buffering. Operates on
/// cleartext frames; decryption (Phase 4) happens before bytes reach this decoder.
/// </summary>
public sealed class SshPacketDecoder
{
    private readonly SshPacketLimits _limits;

    /// <summary>
    /// Initializes a decoder that enforces the given limits.
    /// </summary>
    /// <param name="limits">The protection limits to enforce.</param>
    /// <exception cref="ArgumentNullException">The limits are null.</exception>
    public SshPacketDecoder(SshPacketLimits limits)
    {
        ArgumentNullException.ThrowIfNull(limits);
        _limits = limits;
    }

    /// <summary>
    /// Initializes a decoder with <see cref="SshPacketLimits.Default"/>.
    /// </summary>
    public SshPacketDecoder() : this(SshPacketLimits.Default)
    {
    }

    /// <summary>
    /// Attempts to decode one complete frame from the front of <paramref name="buffer"/>.
    /// On success the buffer is advanced past the frame and the frame's payload references the
    /// original sequence — consume it before releasing the underlying memory. When the buffered
    /// bytes do not yet contain a complete frame, returns false with the buffer unchanged.
    /// </summary>
    /// <param name="buffer">The currently buffered input; advanced past the frame on success.</param>
    /// <param name="frame">The decoded frame boundaries on success.</param>
    /// <returns>True when a complete frame was decoded; false when more input is required.</returns>
    /// <exception cref="SshPacketFormatException">The declared packet_length or padding_length violates the protocol or the configured limits.</exception>
    public bool TryDecode(ref ReadOnlySequence<byte> buffer, out SshPacketFrame frame)
    {
        frame = default;
        if (buffer.Length < 4)
        {
            return false;
        }

        Span<byte> lengthBytes = stackalloc byte[4];
        buffer.Slice(0, 4).CopyTo(lengthBytes);
        uint packetLength = BinaryPrimitives.ReadUInt32BigEndian(lengthBytes);

        if (packetLength < SshPacketLimits.MinimumPacketLength)
        {
            throw new SshPacketFormatException(
                $"Declared packet_length {packetLength} is below the protocol minimum of {SshPacketLimits.MinimumPacketLength}.",
                SshDisconnectReason.ProtocolError);
        }
        if (packetLength > (uint)_limits.MaxPacketLength)
        {
            throw new SshPacketFormatException(
                $"Declared packet_length {packetLength} exceeds the configured maximum of {_limits.MaxPacketLength}.",
                SshDisconnectReason.ProtocolError);
        }

        long totalLength = 4L + packetLength;
        if (buffer.Length < totalLength)
        {
            return false;
        }

        byte paddingLength = ReadByteAt(buffer, 4);
        if (paddingLength < SshPacketGeometry.MinimumPaddingLength)
        {
            throw new SshPacketFormatException(
                $"Declared padding_length {paddingLength} is below the protocol minimum of {SshPacketGeometry.MinimumPaddingLength}.",
                SshDisconnectReason.ProtocolError);
        }
        if (paddingLength > packetLength - 1)
        {
            throw new SshPacketFormatException(
                $"Declared padding_length {paddingLength} leaves no room in packet_length {packetLength}.",
                SshDisconnectReason.ProtocolError);
        }

        long payloadLength = packetLength - 1L - paddingLength;
        ReadOnlySequence<byte> payload = buffer.Slice(5, payloadLength);
        frame = new SshPacketFrame(packetLength, paddingLength, payload);
        buffer = buffer.Slice(totalLength);
        return true;
    }

    private static byte ReadByteAt(in ReadOnlySequence<byte> buffer, int offset)
    {
        ReadOnlySequence<byte> slice = buffer.Slice(offset, 1);
        return slice.FirstSpan[0];
    }
}
