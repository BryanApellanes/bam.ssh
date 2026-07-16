using System.Buffers;

namespace Bam.Ssh.Transport;

/// <summary>
/// The per-direction encryption and message-authentication seam applied around RFC 4253 §6 packet
/// framing. One instance handles one direction of one connection and holds that direction's cipher
/// and MAC state. Before key exchange, <see cref="NonePacketCipher"/> is used (identity, no MAC);
/// after SSH_MSG_NEWKEYS the transport swaps in a real cipher without changing the send/receive
/// loop. The seam separates the three concerns Phase 4 modes vary: framing geometry, MAC size, and
/// how much of the packet is encrypted.
/// </summary>
public interface ISshPacketCipher
{
    /// <summary>
    /// Gets the framing geometry (block size and whether the length field is encrypted) the
    /// encoder must use so padding aligns correctly for this cipher.
    /// </summary>
    SshPacketGeometry Geometry { get; }

    /// <summary>
    /// Gets the number of MAC bytes appended after each packet (0 for AEAD modes that authenticate
    /// inline and for the "none" cipher).
    /// </summary>
    int MacLength { get; }

    /// <summary>
    /// Gets the number of leading bytes that must be present before <see cref="DecryptLength"/> can
    /// determine the packet length — 4 for modes with a cleartext or separately-decryptable length,
    /// or the cipher block size for modes that encrypt the length within the first block.
    /// </summary>
    int LengthPeekSize { get; }

    /// <summary>
    /// Transforms a fully framed cleartext packet (length + padding_length + payload + padding)
    /// into the on-the-wire form for this direction — encrypting and appending the MAC as the mode
    /// requires — and writes it to <paramref name="output"/>. The identity implementation copies
    /// the framed bytes unchanged.
    /// </summary>
    /// <param name="framedPacket">The cleartext framed packet from the encoder.</param>
    /// <param name="sequenceNumber">The sequence number assigned to this packet (for the MAC).</param>
    /// <param name="output">The destination for the wire bytes.</param>
    void TransformOutgoing(ReadOnlySpan<byte> framedPacket, uint sequenceNumber, IBufferWriter<byte> output);

    /// <summary>
    /// Determines the cleartext packet_length from the first <see cref="LengthPeekSize"/> bytes of
    /// an incoming packet, decrypting them into <paramref name="decryptedLength"/> if the mode
    /// encrypts the length. For the "none" cipher this reads the cleartext big-endian length. The
    /// sequence number is supplied because chacha20-poly1305 keys the length cipher on it; modes with
    /// a cleartext or counter-decrypted length ignore it.
    /// </summary>
    /// <param name="peek">The first <see cref="LengthPeekSize"/> bytes of the incoming packet.</param>
    /// <param name="sequenceNumber">The sequence number the incoming packet will be assigned.</param>
    /// <param name="decryptedLength">Receives the four cleartext length bytes.</param>
    /// <returns>The packet_length field value.</returns>
    uint DecryptLength(ReadOnlySpan<byte> peek, uint sequenceNumber, Span<byte> decryptedLength);

    /// <summary>
    /// Authenticates and decrypts a complete incoming packet (the whole ciphertext plus its MAC)
    /// into <paramref name="output"/> as the cleartext framed packet. The identity implementation
    /// copies the input unchanged.
    /// </summary>
    /// <param name="wirePacket">The complete on-the-wire packet including any trailing MAC.</param>
    /// <param name="sequenceNumber">The sequence number assigned to this packet (for MAC verification).</param>
    /// <param name="output">The destination for the cleartext framed packet.</param>
    /// <returns>True when authentication succeeded; false when the MAC did not verify.</returns>
    bool VerifyAndDecrypt(ReadOnlySpan<byte> wirePacket, uint sequenceNumber, IBufferWriter<byte> output);
}
