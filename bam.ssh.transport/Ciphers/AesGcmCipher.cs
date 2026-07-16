using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Bam.Ssh.Transport;

/// <summary>
/// The <c>aes256-gcm@openssh.com</c> / <c>aes128-gcm@openssh.com</c> authenticated cipher for one
/// connection direction (RFC 5647, OpenSSH PROTOCOL). The 4-byte packet_length travels in the clear
/// and is authenticated as additional data; the padding_length, payload, and padding are encrypted
/// with AES-GCM and followed by the 16-byte tag. The 12-byte nonce is initialized from the derived
/// IV — a 4-byte fixed prefix and an 8-byte invocation counter — and the counter is incremented once
/// per packet (RFC 5647 §7.1), never reused. Uses the .NET <see cref="AesGcm"/> primitive. One
/// instance serves one direction; not thread-safe.
/// </summary>
public sealed class AesGcmCipher : ISshPacketCipher, IDisposable
{
    private const int TagLength = 16;
    private const int LengthFieldLength = 4;
    private const int NonceLength = 12;
    private const int FixedNonceLength = 4;

    private readonly AesGcm _aesGcm;
    private readonly byte[] _nonce;

    /// <summary>
    /// Initializes the cipher for one direction.
    /// </summary>
    /// <param name="key">The encryption key: 16 bytes (aes128-gcm) or 32 bytes (aes256-gcm).</param>
    /// <param name="iv">The initial IV; its first 12 bytes seed the nonce.</param>
    /// <exception cref="ArgumentException">The key is not 16 or 32 bytes, or the IV is shorter than 12 bytes.</exception>
    public AesGcmCipher(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
    {
        if (key.Length != 16 && key.Length != 32)
        {
            throw new ArgumentException("aes-gcm requires a 16- or 32-byte key.", nameof(key));
        }
        if (iv.Length < NonceLength)
        {
            throw new ArgumentException($"aes-gcm requires at least {NonceLength} IV bytes.", nameof(iv));
        }
        _aesGcm = new AesGcm(key, TagLength);
        _nonce = iv.Slice(0, NonceLength).ToArray();
    }

    /// <summary>
    /// Gets the framing geometry: 16-byte alignment with the length field excluded (it is cleartext
    /// AAD, not part of the encrypted region's padding alignment).
    /// </summary>
    public SshPacketGeometry Geometry => new SshPacketGeometry(16, false);

    /// <summary>Gets the GCM tag length appended to each packet (16 bytes).</summary>
    public int MacLength => TagLength;

    /// <summary>Gets the length-peek size: the 4-byte cleartext length field.</summary>
    public int LengthPeekSize => LengthFieldLength;

    /// <summary>
    /// Writes the cleartext length, GCM-encrypts the remainder with the length as additional data,
    /// appends the tag, and advances the nonce.
    /// </summary>
    /// <param name="framedPacket">The cleartext framed packet (length ‖ padding_length ‖ payload ‖ padding).</param>
    /// <param name="sequenceNumber">Unused; the GCM nonce is an internal per-packet counter.</param>
    /// <param name="output">The destination for the wire bytes.</param>
    /// <exception cref="ArgumentNullException">The output is null.</exception>
    public void TransformOutgoing(ReadOnlySpan<byte> framedPacket, uint sequenceNumber, IBufferWriter<byte> output)
    {
        ArgumentNullException.ThrowIfNull(output);
        int plaintextLength = framedPacket.Length - LengthFieldLength;
        int wireLength = LengthFieldLength + plaintextLength + TagLength;
        Span<byte> destination = output.GetSpan(wireLength).Slice(0, wireLength);

        ReadOnlySpan<byte> length = framedPacket.Slice(0, LengthFieldLength);
        length.CopyTo(destination.Slice(0, LengthFieldLength));

        Span<byte> ciphertext = destination.Slice(LengthFieldLength, plaintextLength);
        Span<byte> tag = destination.Slice(LengthFieldLength + plaintextLength, TagLength);
        _aesGcm.Encrypt(_nonce, framedPacket.Slice(LengthFieldLength), ciphertext, tag, length);

        IncrementNonce();
        output.Advance(wireLength);
    }

    /// <summary>
    /// Reads the cleartext big-endian packet_length from the first four bytes.
    /// </summary>
    /// <param name="peek">The first four (cleartext) length bytes.</param>
    /// <param name="sequenceNumber">Unused for aes-gcm.</param>
    /// <param name="decryptedLength">Receives a copy of the four length bytes.</param>
    /// <returns>The packet_length field value.</returns>
    public uint DecryptLength(ReadOnlySpan<byte> peek, uint sequenceNumber, Span<byte> decryptedLength)
    {
        peek.Slice(0, LengthFieldLength).CopyTo(decryptedLength);
        return BinaryPrimitives.ReadUInt32BigEndian(peek);
    }

    /// <summary>
    /// Verifies the tag and decrypts the packet with the length as additional data, then advances the
    /// nonce on success.
    /// </summary>
    /// <param name="wirePacket">Cleartext-length ‖ ciphertext ‖ 16-byte tag.</param>
    /// <param name="sequenceNumber">Unused for aes-gcm.</param>
    /// <param name="output">The destination for the cleartext framed packet.</param>
    /// <returns>True when the tag verified; false when authentication failed.</returns>
    /// <exception cref="ArgumentNullException">The output is null.</exception>
    public bool VerifyAndDecrypt(ReadOnlySpan<byte> wirePacket, uint sequenceNumber, IBufferWriter<byte> output)
    {
        ArgumentNullException.ThrowIfNull(output);
        int ciphertextLength = wirePacket.Length - LengthFieldLength - TagLength;
        if (ciphertextLength < 0)
        {
            return false;
        }

        ReadOnlySpan<byte> length = wirePacket.Slice(0, LengthFieldLength);
        ReadOnlySpan<byte> ciphertext = wirePacket.Slice(LengthFieldLength, ciphertextLength);
        ReadOnlySpan<byte> tag = wirePacket.Slice(LengthFieldLength + ciphertextLength, TagLength);

        int frameLength = LengthFieldLength + ciphertextLength;
        Span<byte> destination = output.GetSpan(frameLength).Slice(0, frameLength);
        length.CopyTo(destination.Slice(0, LengthFieldLength));

        try
        {
            _aesGcm.Decrypt(_nonce, ciphertext, tag, destination.Slice(LengthFieldLength, ciphertextLength), length);
        }
        catch (AuthenticationTagMismatchException)
        {
            return false;
        }

        IncrementNonce();
        output.Advance(frameLength);
        return true;
    }

    /// <summary>
    /// Releases the underlying <see cref="AesGcm"/> instance.
    /// </summary>
    public void Dispose()
    {
        _aesGcm.Dispose();
    }

    private void IncrementNonce()
    {
        // RFC 5647 §7.1: the low 8 bytes are a big-endian invocation counter incremented per packet;
        // the fixed 4-byte prefix is unchanged.
        for (int i = NonceLength - 1; i >= FixedNonceLength; i--)
        {
            if (++_nonce[i] != 0)
            {
                break;
            }
        }
    }
}
