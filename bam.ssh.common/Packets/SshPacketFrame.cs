using System.Buffers;

namespace Bam.Ssh;

/// <summary>
/// The decoded boundaries of one RFC 4253 §6 binary packet: the declared lengths plus the
/// payload as a slice of the decoder's input sequence. The payload references the caller's
/// buffer — consume or copy it before advancing the underlying pipe reader past the frame,
/// or the memory it points into may be reused.
/// </summary>
public readonly struct SshPacketFrame
{
    /// <summary>
    /// Initializes a frame from validated component boundaries. Constructed by
    /// <see cref="SshPacketDecoder"/>; the values are trusted as already validated.
    /// </summary>
    /// <param name="packetLength">The packet_length field value.</param>
    /// <param name="paddingLength">The padding_length field value.</param>
    /// <param name="payload">The payload bytes as a slice of the decode input.</param>
    public SshPacketFrame(uint packetLength, byte paddingLength, ReadOnlySequence<byte> payload)
    {
        PacketLength = packetLength;
        PaddingLength = paddingLength;
        Payload = payload;
    }

    /// <summary>
    /// Gets the packet_length field value: the byte count of padding_length + payload + padding
    /// (excluding the length field itself and any MAC).
    /// </summary>
    public uint PacketLength { get; }

    /// <summary>
    /// Gets the padding_length field value (4–255).
    /// </summary>
    public byte PaddingLength { get; }

    /// <summary>
    /// Gets the payload bytes. A slice of the decoder's input — valid only until the underlying
    /// buffer is advanced or released.
    /// </summary>
    public ReadOnlySequence<byte> Payload { get; }

    /// <summary>
    /// Gets the total number of stream bytes this frame consumed: the 4-byte length field plus
    /// <see cref="PacketLength"/> (MAC bytes, when present, are handled by the cipher layer).
    /// </summary>
    public long TotalLength => 4L + PacketLength;
}
