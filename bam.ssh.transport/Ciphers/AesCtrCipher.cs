using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Bam.Ssh.Transport;

/// <summary>
/// The <c>aes256-ctr</c> / <c>aes128-ctr</c> cipher combined with an HMAC-SHA2 MAC for one connection
/// direction (RFC 4344 counter mode, RFC 4253 §6.4 encrypt-and-MAC, RFC 6668 MACs). The entire
/// packet — including the 4-byte length — is encrypted with AES in counter mode; the MAC is computed
/// over the sequence number concatenated with the <em>cleartext</em> packet and appended in the
/// clear. The 128-bit counter is initialized from the derived IV and increments per 16-byte block,
/// continuously across the whole session (never reset per packet). AES-CTR is built from the .NET
/// <see cref="Aes"/> ECB primitive (the BCL exposes no CTR mode); the MAC uses
/// <see cref="IncrementalHash"/> HMAC. One instance serves one direction; not thread-safe.
/// </summary>
public sealed class AesCtrCipher : ISshPacketCipher, IDisposable
{
    private const int BlockLength = 16;

    // Counter blocks are encrypted in batches of this many per one-shot ECB call rather than one block at a
    // time, cutting the per-packet call count (and its per-call overhead) by this factor.
    private const int KeystreamBatchBlocks = 64;

    private readonly Aes _aes;
    private readonly byte[] _counter;
    private readonly int _macLength;
    // The HMAC is created once and reset per packet (GetHashAndReset) rather than reallocated each call.
    private readonly IncrementalHash _mac;

    /// <summary>
    /// Initializes the cipher for one direction.
    /// </summary>
    /// <param name="key">The encryption key: 16 bytes (aes128-ctr) or 32 bytes (aes256-ctr).</param>
    /// <param name="iv">The 16-byte initial counter.</param>
    /// <param name="integrityKey">The HMAC key (32 bytes for hmac-sha2-256, 64 for hmac-sha2-512).</param>
    /// <param name="macAlgorithm">The HMAC hash algorithm (<see cref="HashAlgorithmName.SHA256"/> or <see cref="HashAlgorithmName.SHA512"/>).</param>
    /// <param name="macLength">The MAC output length in bytes (32 or 64).</param>
    /// <exception cref="ArgumentException">The key is not 16 or 32 bytes, or the IV is not 16 bytes.</exception>
    public AesCtrCipher(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> integrityKey, HashAlgorithmName macAlgorithm, int macLength)
    {
        if (key.Length != 16 && key.Length != 32)
        {
            throw new ArgumentException("aes-ctr requires a 16- or 32-byte key.", nameof(key));
        }
        if (iv.Length < BlockLength)
        {
            throw new ArgumentException($"aes-ctr requires at least a {BlockLength}-byte IV.", nameof(iv));
        }
        _aes = Aes.Create();
        _aes.Key = key.ToArray();
        _counter = iv.Slice(0, BlockLength).ToArray();
        _macLength = macLength;
        _mac = IncrementalHash.CreateHMAC(macAlgorithm, integrityKey);
    }

    /// <summary>
    /// Gets the framing geometry: 16-byte alignment with the length field encrypted (the whole packet,
    /// length included, is under the counter-mode cipher).
    /// </summary>
    public SshPacketGeometry Geometry => new SshPacketGeometry(BlockLength, true);

    /// <summary>Gets the HMAC length appended to each packet (32 for SHA-256, 64 for SHA-512).</summary>
    public int MacLength => _macLength;

    /// <summary>Gets the length-peek size: a full cipher block, since the length field is encrypted.</summary>
    public int LengthPeekSize => BlockLength;

    /// <summary>
    /// Computes the MAC over the sequence number and cleartext packet, encrypts the whole packet in
    /// counter mode, and writes ciphertext ‖ MAC.
    /// </summary>
    /// <param name="framedPacket">The cleartext framed packet (length ‖ padding_length ‖ payload ‖ padding).</param>
    /// <param name="sequenceNumber">The packet sequence number, bound into the MAC.</param>
    /// <param name="output">The destination for the wire bytes.</param>
    /// <exception cref="ArgumentNullException">The output is null.</exception>
    public void TransformOutgoing(ReadOnlySpan<byte> framedPacket, uint sequenceNumber, IBufferWriter<byte> output)
    {
        ArgumentNullException.ThrowIfNull(output);
        int wireLength = framedPacket.Length + _macLength;
        Span<byte> destination = output.GetSpan(wireLength).Slice(0, wireLength);

        ComputeMac(sequenceNumber, framedPacket, destination.Slice(framedPacket.Length, _macLength));
        CounterTransform(framedPacket, destination.Slice(0, framedPacket.Length));

        output.Advance(wireLength);
    }

    /// <summary>
    /// Decrypts the first cipher block to read the encrypted packet_length, without advancing the
    /// counter (the whole packet is re-decrypted from the same counter in <see cref="VerifyAndDecrypt"/>).
    /// </summary>
    /// <param name="peek">The first 16 (encrypted) bytes of the packet.</param>
    /// <param name="sequenceNumber">Unused for aes-ctr.</param>
    /// <param name="decryptedLength">Receives the four cleartext length bytes.</param>
    /// <returns>The packet_length field value.</returns>
    public uint DecryptLength(ReadOnlySpan<byte> peek, uint sequenceNumber, Span<byte> decryptedLength)
    {
        Span<byte> keystream = stackalloc byte[BlockLength];
        _aes.EncryptEcb(_counter, keystream, PaddingMode.None);
        for (int i = 0; i < 4; i++)
        {
            decryptedLength[i] = (byte)(peek[i] ^ keystream[i]);
        }
        return BinaryPrimitives.ReadUInt32BigEndian(decryptedLength);
    }

    /// <summary>
    /// Decrypts the whole packet in counter mode, then verifies the trailing MAC over the sequence
    /// number and recovered cleartext. The counter advances by the packet's block count.
    /// </summary>
    /// <param name="wirePacket">Ciphertext ‖ MAC.</param>
    /// <param name="sequenceNumber">The packet sequence number, bound into the MAC.</param>
    /// <param name="output">The destination for the cleartext framed packet.</param>
    /// <returns>True when the MAC verified; false otherwise.</returns>
    /// <exception cref="ArgumentNullException">The output is null.</exception>
    public bool VerifyAndDecrypt(ReadOnlySpan<byte> wirePacket, uint sequenceNumber, IBufferWriter<byte> output)
    {
        ArgumentNullException.ThrowIfNull(output);
        int ciphertextLength = wirePacket.Length - _macLength;
        if (ciphertextLength <= 0 || ciphertextLength % BlockLength != 0)
        {
            return false;
        }

        Span<byte> plaintext = output.GetSpan(ciphertextLength).Slice(0, ciphertextLength);
        CounterTransform(wirePacket.Slice(0, ciphertextLength), plaintext);

        Span<byte> computedMac = stackalloc byte[64];
        computedMac = computedMac.Slice(0, _macLength);
        ComputeMac(sequenceNumber, plaintext, computedMac);
        if (!CryptographicOperations.FixedTimeEquals(computedMac, wirePacket.Slice(ciphertextLength, _macLength)))
        {
            return false;
        }

        output.Advance(ciphertextLength);
        return true;
    }

    /// <summary>
    /// Releases the underlying <see cref="Aes"/> instance and the HMAC.
    /// </summary>
    public void Dispose()
    {
        _aes.Dispose();
        _mac.Dispose();
    }

    private void CounterTransform(ReadOnlySpan<byte> input, Span<byte> output)
    {
        Span<byte> counter = stackalloc byte[BlockLength];
        _counter.CopyTo(counter);
        // Generate the keystream a batch of blocks at a time: fill the counter blocks, encrypt them in one
        // ECB call, then XOR. This is bit-for-bit identical to per-block encryption (each ECB block is
        // independent) but cuts the number of one-shot calls — and their overhead — by the batch factor.
        Span<byte> counterBatch = stackalloc byte[BlockLength * KeystreamBatchBlocks];
        Span<byte> keystreamBatch = stackalloc byte[BlockLength * KeystreamBatchBlocks];

        int offset = 0;
        while (offset < input.Length)
        {
            int remaining = input.Length - offset;
            int blocks = Math.Min(KeystreamBatchBlocks, (remaining + BlockLength - 1) / BlockLength);
            for (int b = 0; b < blocks; b++)
            {
                counter.CopyTo(counterBatch.Slice(b * BlockLength, BlockLength));
                IncrementCounter(counter);
            }

            int batchBytes = blocks * BlockLength;
            _aes.EncryptEcb(counterBatch.Slice(0, batchBytes), keystreamBatch.Slice(0, batchBytes), PaddingMode.None);

            int chunk = Math.Min(batchBytes, remaining);
            for (int i = 0; i < chunk; i++)
            {
                output[offset + i] = (byte)(input[offset + i] ^ keystreamBatch[i]);
            }
            offset += chunk;
        }

        counter.CopyTo(_counter);
    }

    private void ComputeMac(uint sequenceNumber, ReadOnlySpan<byte> cleartextPacket, Span<byte> mac)
    {
        Span<byte> sequence = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(sequence, sequenceNumber);
        _mac.AppendData(sequence);
        _mac.AppendData(cleartextPacket);
        Span<byte> full = stackalloc byte[64];
        _mac.GetHashAndReset(full);
        full.Slice(0, _macLength).CopyTo(mac);
    }

    private static void IncrementCounter(Span<byte> counter)
    {
        for (int i = counter.Length - 1; i >= 0; i--)
        {
            if (++counter[i] != 0)
            {
                break;
            }
        }
    }
}
