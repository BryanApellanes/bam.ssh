using System.Buffers;
using System.Security.Cryptography;

namespace Bam.Ssh.Transport;

/// <summary>
/// Derives session key material from the shared secret and exchange hash per RFC 4253 §7.2. Each key
/// is <c>K1 = HASH(K || H || X || session_id)</c> where X is a single distinguishing letter (A–F),
/// K is encoded as an mpint, and H and session_id are raw bytes. If more bytes are needed than one
/// digest yields, the key is extended by <c>K2 = HASH(K || H || K1)</c>, <c>K3 = HASH(K || H || K1 || K2)</c>,
/// and so on, concatenated and truncated to the requested length.
/// </summary>
public static class SshKeyDerivation
{
    /// <summary>The RFC 4253 §7.2 letter for the client-to-server initial IV.</summary>
    public const byte InitialIvClientToServer = (byte)'A';

    /// <summary>The RFC 4253 §7.2 letter for the server-to-client initial IV.</summary>
    public const byte InitialIvServerToClient = (byte)'B';

    /// <summary>The RFC 4253 §7.2 letter for the client-to-server encryption key.</summary>
    public const byte EncryptionKeyClientToServer = (byte)'C';

    /// <summary>The RFC 4253 §7.2 letter for the server-to-client encryption key.</summary>
    public const byte EncryptionKeyServerToClient = (byte)'D';

    /// <summary>The RFC 4253 §7.2 letter for the client-to-server integrity (MAC) key.</summary>
    public const byte IntegrityKeyClientToServer = (byte)'E';

    /// <summary>The RFC 4253 §7.2 letter for the server-to-client integrity (MAC) key.</summary>
    public const byte IntegrityKeyServerToClient = (byte)'F';

    /// <summary>
    /// Derives one key of the requested length.
    /// </summary>
    /// <param name="hashAlgorithm">The digest for the negotiated key-exchange method.</param>
    /// <param name="sharedSecret">K — the shared secret as an unsigned big-endian magnitude.</param>
    /// <param name="exchangeHash">H — the exchange hash of this key exchange.</param>
    /// <param name="letter">The distinguishing letter (A–F); see the constants on this type.</param>
    /// <param name="sessionId">The session identifier (H of the first key exchange).</param>
    /// <param name="length">The number of key bytes required.</param>
    /// <returns>The derived key of exactly <paramref name="length"/> bytes.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The length is negative.</exception>
    public static byte[] DeriveKey(
        HashAlgorithmName hashAlgorithm,
        ReadOnlySpan<byte> sharedSecret,
        ReadOnlySpan<byte> exchangeHash,
        byte letter,
        ReadOnlySpan<byte> sessionId,
        int length)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(length);
        if (length == 0)
        {
            return Array.Empty<byte>();
        }

        // Encode K once as an mpint prefix shared by every digest in the chain.
        using PooledBufferWriter secretWriter = new PooledBufferWriter(sharedSecret.Length + 8);
        SshWireWriter mpintWriter = new SshWireWriter(secretWriter);
        mpintWriter.WriteMultiPrecisionInteger(sharedSecret);
        ReadOnlySpan<byte> encodedSecret = secretWriter.WrittenSpan;

        byte[] result = new byte[length];
        int produced = 0;

        // K1 = HASH(K || H || letter || session_id)
        using PooledBufferWriter first = new PooledBufferWriter(encodedSecret.Length + exchangeHash.Length + sessionId.Length + 1);
        first.Write(encodedSecret);
        first.Write(exchangeHash);
        first.GetSpan(1)[0] = letter;
        first.Advance(1);
        first.Write(sessionId);
        byte[] block = SshExchangeHash.ComputeDigest(hashAlgorithm, first.WrittenSpan);
        produced = Append(result, produced, block);

        // Extend: K(n+1) = HASH(K || H || K1 || ... || Kn)
        using PooledBufferWriter extension = new PooledBufferWriter(encodedSecret.Length + exchangeHash.Length + length);
        extension.Write(encodedSecret);
        extension.Write(exchangeHash);
        while (produced < length)
        {
            extension.Write(block);
            block = SshExchangeHash.ComputeDigest(hashAlgorithm, extension.WrittenSpan);
            produced = Append(result, produced, block);
        }

        return result;
    }

    private static int Append(byte[] destination, int offset, ReadOnlySpan<byte> block)
    {
        int take = Math.Min(block.Length, destination.Length - offset);
        block.Slice(0, take).CopyTo(destination.AsSpan(offset));
        return offset + take;
    }
}
