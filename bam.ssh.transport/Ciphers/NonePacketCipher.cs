using System.Buffers;
using System.Buffers.Binary;

namespace Bam.Ssh.Transport;

/// <summary>
/// The cleartext identity <see cref="ISshPacketCipher"/> used before key exchange and whenever the
/// negotiated cipher/MAC is "none" (RFC 4253 §6.3, §6.4). It applies no encryption and no MAC:
/// outgoing framed packets go to the wire verbatim, and incoming packets are already cleartext.
/// Its geometry is an 8-byte block with the length field counted in padding alignment, matching the
/// RFC's pre-kex framing. Stateless and thread-safe; use <see cref="Instance"/>.
/// </summary>
public sealed class NonePacketCipher : ISshPacketCipher
{
    /// <summary>
    /// Gets the shared instance. The cipher is stateless, so one serves every direction.
    /// </summary>
    public static NonePacketCipher Instance { get; } = new NonePacketCipher();

    /// <summary>
    /// Gets the pre-kex framing geometry: 8-byte block, length field included in alignment.
    /// </summary>
    public SshPacketGeometry Geometry => SshPacketGeometry.Default;

    /// <summary>
    /// Gets the MAC length, which is zero for the "none" cipher.
    /// </summary>
    public int MacLength => 0;

    /// <summary>
    /// Gets the length-peek size, which is the 4-byte cleartext length field.
    /// </summary>
    public int LengthPeekSize => 4;

    /// <summary>
    /// Copies the framed packet to the output unchanged (no encryption, no MAC).
    /// </summary>
    /// <param name="framedPacket">The cleartext framed packet.</param>
    /// <param name="sequenceNumber">Unused for the identity cipher.</param>
    /// <param name="output">The destination for the wire bytes.</param>
    public void TransformOutgoing(ReadOnlySpan<byte> framedPacket, uint sequenceNumber, IBufferWriter<byte> output)
    {
        ArgumentNullException.ThrowIfNull(output);
        Span<byte> destination = output.GetSpan(framedPacket.Length);
        framedPacket.CopyTo(destination);
        output.Advance(framedPacket.Length);
    }

    /// <summary>
    /// Reads the cleartext big-endian packet_length from the first four bytes.
    /// </summary>
    /// <param name="peek">The first four bytes of the incoming packet.</param>
    /// <param name="sequenceNumber">Unused for the identity cipher.</param>
    /// <param name="decryptedLength">Receives a copy of those four bytes.</param>
    /// <returns>The packet_length field value.</returns>
    public uint DecryptLength(ReadOnlySpan<byte> peek, uint sequenceNumber, Span<byte> decryptedLength)
    {
        peek.Slice(0, 4).CopyTo(decryptedLength);
        return BinaryPrimitives.ReadUInt32BigEndian(peek);
    }

    /// <summary>
    /// Copies the incoming packet to the output unchanged (already cleartext, no MAC to verify).
    /// </summary>
    /// <param name="wirePacket">The incoming cleartext framed packet.</param>
    /// <param name="sequenceNumber">Unused for the identity cipher.</param>
    /// <param name="output">The destination for the cleartext framed packet.</param>
    /// <returns>Always true — there is no MAC to fail.</returns>
    public bool VerifyAndDecrypt(ReadOnlySpan<byte> wirePacket, uint sequenceNumber, IBufferWriter<byte> output)
    {
        ArgumentNullException.ThrowIfNull(output);
        Span<byte> destination = output.GetSpan(wirePacket.Length);
        wirePacket.CopyTo(destination);
        output.Advance(wirePacket.Length);
        return true;
    }
}
