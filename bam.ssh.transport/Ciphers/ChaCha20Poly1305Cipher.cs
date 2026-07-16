using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Bam.Ssh.Transport;

/// <summary>
/// The <c>chacha20-poly1305@openssh.com</c> authenticated cipher for one connection direction
/// (OpenSSH PROTOCOL.chacha20poly1305). It splits the 64-byte key into two ChaCha20 keys: K_2
/// encrypts the payload and K_1 encrypts the 4-byte packet_length field separately, so a receiver
/// can decrypt the length before it has the whole packet. Each packet's nonce is its 64-bit
/// big-endian sequence number; the Poly1305 one-time key is the first ChaCha20 block (counter 0) of
/// the K_2 keystream, and the payload is encrypted from counter 1. The tag authenticates the
/// encrypted length concatenated with the encrypted payload. .NET's <see cref="ChaCha20Poly1305"/>
/// cannot express this two-key construction, so BouncyCastle's raw ChaCha20 and Poly1305 are used
/// (D-009 scope extension). One instance serves one direction; not thread-safe.
/// </summary>
public sealed class ChaCha20Poly1305Cipher : ISshPacketCipher
{
    /// <summary>The total key length in bytes this cipher consumes from the derived key material.</summary>
    public const int KeyLength = 64;

    private const int TagLength = 16;
    private const int LengthFieldLength = 4;
    private const int PolyKeyLength = 32;
    private const int ChaChaBlockLength = 64;

    private readonly byte[] _payloadKey;
    private readonly byte[] _lengthKey;

    /// <summary>
    /// Initializes the cipher for one direction from its 64-byte key.
    /// </summary>
    /// <param name="key">The 64-byte key: the first 32 bytes key the payload cipher (K_2), the last 32 the length cipher (K_1).</param>
    /// <exception cref="ArgumentNullException">The key is null.</exception>
    /// <exception cref="ArgumentException">The key is not 64 bytes.</exception>
    public ChaCha20Poly1305Cipher(ReadOnlySpan<byte> key)
    {
        if (key.Length != KeyLength)
        {
            throw new ArgumentException($"chacha20-poly1305 requires a {KeyLength}-byte key.", nameof(key));
        }
        _payloadKey = key.Slice(0, PolyKeyLength).ToArray();
        _lengthKey = key.Slice(PolyKeyLength, PolyKeyLength).ToArray();
    }

    /// <summary>
    /// Gets the framing geometry: 8-byte alignment with the length field excluded (it is encrypted
    /// separately and does not participate in payload padding alignment).
    /// </summary>
    public SshPacketGeometry Geometry => new SshPacketGeometry(8, false);

    /// <summary>Gets the Poly1305 tag length appended to each packet (16 bytes).</summary>
    public int MacLength => TagLength;

    /// <summary>Gets the length-peek size: the 4-byte separately-decryptable length field.</summary>
    public int LengthPeekSize => LengthFieldLength;

    /// <summary>
    /// Encrypts the length field and payload with the two ChaCha20 keys, appends the Poly1305 tag,
    /// and writes encrypted-length ‖ encrypted-payload ‖ tag.
    /// </summary>
    /// <param name="framedPacket">The cleartext framed packet (length ‖ padding_length ‖ payload ‖ padding).</param>
    /// <param name="sequenceNumber">The packet sequence number, used as the ChaCha20 nonce.</param>
    /// <param name="output">The destination for the wire bytes.</param>
    /// <exception cref="ArgumentNullException">The output is null.</exception>
    public void TransformOutgoing(ReadOnlySpan<byte> framedPacket, uint sequenceNumber, IBufferWriter<byte> output)
    {
        ArgumentNullException.ThrowIfNull(output);
        int payloadLength = framedPacket.Length - LengthFieldLength;
        int wireLength = LengthFieldLength + payloadLength + TagLength;
        Span<byte> destination = output.GetSpan(wireLength).Slice(0, wireLength);

        Span<byte> nonce = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(nonce, sequenceNumber);

        Span<byte> encryptedLength = destination.Slice(0, LengthFieldLength);
        EncryptLength(framedPacket.Slice(0, LengthFieldLength), nonce, encryptedLength);

        Span<byte> polyKey = stackalloc byte[PolyKeyLength];
        ChaChaEngine payloadCipher = CreatePayloadCipher(nonce, polyKey);

        Span<byte> encryptedPayload = destination.Slice(LengthFieldLength, payloadLength);
        payloadCipher.ProcessBytes(framedPacket.Slice(LengthFieldLength), encryptedPayload);

        Span<byte> tag = destination.Slice(LengthFieldLength + payloadLength, TagLength);
        ComputePoly1305(polyKey, destination.Slice(0, LengthFieldLength + payloadLength), tag);

        output.Advance(wireLength);
    }

    /// <summary>
    /// Decrypts the 4-byte length field with the K_1 ChaCha20 keystream for the packet's sequence number.
    /// </summary>
    /// <param name="peek">The first four (encrypted) length bytes.</param>
    /// <param name="sequenceNumber">The packet sequence number, used as the ChaCha20 nonce.</param>
    /// <param name="decryptedLength">Receives the four cleartext length bytes.</param>
    /// <returns>The packet_length field value.</returns>
    public uint DecryptLength(ReadOnlySpan<byte> peek, uint sequenceNumber, Span<byte> decryptedLength)
    {
        Span<byte> nonce = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(nonce, sequenceNumber);
        EncryptLength(peek.Slice(0, LengthFieldLength), nonce, decryptedLength.Slice(0, LengthFieldLength));
        return BinaryPrimitives.ReadUInt32BigEndian(decryptedLength);
    }

    /// <summary>
    /// Verifies the Poly1305 tag over the encrypted length and payload, and on success decrypts both
    /// into the cleartext framed packet. The tag is checked before any plaintext is produced.
    /// </summary>
    /// <param name="wirePacket">Encrypted-length ‖ encrypted-payload ‖ 16-byte tag.</param>
    /// <param name="sequenceNumber">The packet sequence number, used as the ChaCha20 nonce.</param>
    /// <param name="output">The destination for the cleartext framed packet.</param>
    /// <returns>True when the tag verified; false otherwise.</returns>
    /// <exception cref="ArgumentNullException">The output is null.</exception>
    public bool VerifyAndDecrypt(ReadOnlySpan<byte> wirePacket, uint sequenceNumber, IBufferWriter<byte> output)
    {
        ArgumentNullException.ThrowIfNull(output);
        int cipherTextLength = wirePacket.Length - TagLength;
        int payloadLength = cipherTextLength - LengthFieldLength;
        if (payloadLength < 0)
        {
            return false;
        }

        Span<byte> nonce = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(nonce, sequenceNumber);

        Span<byte> polyKey = stackalloc byte[PolyKeyLength];
        ChaChaEngine payloadCipher = CreatePayloadCipher(nonce, polyKey);

        Span<byte> computedTag = stackalloc byte[TagLength];
        ComputePoly1305(polyKey, wirePacket.Slice(0, cipherTextLength), computedTag);
        if (!CryptographicOperations.FixedTimeEquals(computedTag, wirePacket.Slice(cipherTextLength, TagLength)))
        {
            return false;
        }

        Span<byte> destination = output.GetSpan(cipherTextLength).Slice(0, cipherTextLength);
        EncryptLength(wirePacket.Slice(0, LengthFieldLength), nonce, destination.Slice(0, LengthFieldLength));
        payloadCipher.ProcessBytes(wirePacket.Slice(LengthFieldLength, payloadLength), destination.Slice(LengthFieldLength, payloadLength));
        output.Advance(cipherTextLength);
        return true;
    }

    private void EncryptLength(ReadOnlySpan<byte> input, ReadOnlySpan<byte> nonce, Span<byte> output)
    {
        ChaChaEngine lengthCipher = new ChaChaEngine();
        lengthCipher.Init(forEncryption: true, new ParametersWithIV(new KeyParameter(_lengthKey), nonce.ToArray()));
        lengthCipher.ProcessBytes(input, output);
    }

    private ChaChaEngine CreatePayloadCipher(ReadOnlySpan<byte> nonce, Span<byte> polyKey)
    {
        ChaChaEngine payloadCipher = new ChaChaEngine();
        payloadCipher.Init(forEncryption: true, new ParametersWithIV(new KeyParameter(_payloadKey), nonce.ToArray()));

        // Consume the full first 64-byte keystream block (counter 0): its first 32 bytes are the
        // Poly1305 one-time key; the rest is discarded. This leaves the engine positioned at counter
        // 1, which is where the payload keystream begins — equivalent to OpenSSH's explicit counter reset.
        Span<byte> firstBlock = stackalloc byte[ChaChaBlockLength];
        Span<byte> zero = stackalloc byte[ChaChaBlockLength];
        payloadCipher.ProcessBytes(zero, firstBlock);
        firstBlock.Slice(0, PolyKeyLength).CopyTo(polyKey);
        return payloadCipher;
    }

    private static void ComputePoly1305(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data, Span<byte> tag)
    {
        Poly1305 poly = new Poly1305();
        poly.Init(new KeyParameter(key.ToArray()));
        byte[] buffer = data.ToArray();
        poly.BlockUpdate(buffer, 0, buffer.Length);
        byte[] output = new byte[TagLength];
        poly.DoFinal(output, 0);
        output.CopyTo(tag);
    }
}
