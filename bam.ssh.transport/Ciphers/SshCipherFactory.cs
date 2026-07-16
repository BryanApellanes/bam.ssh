using System.Security.Cryptography;

namespace Bam.Ssh.Transport;

/// <summary>
/// Builds the <see cref="ISshPacketCipher"/> for a negotiated cipher (and, for non-AEAD ciphers, MAC)
/// name from the direction-appropriate key material derived in key exchange. AEAD ciphers
/// (chacha20-poly1305, aes-gcm) authenticate inline and ignore the negotiated MAC name; the
/// counter-mode ciphers pair with an HMAC-SHA2. Each key argument is a full 64-byte derived block
/// (RFC 4253 §7.2 prefix relationship), from which this slices the exact prefix each algorithm needs.
/// </summary>
public static class SshCipherFactory
{
    private const int Sha256MacKeyLength = 32;
    private const int Sha512MacKeyLength = 64;
    private const int Sha256MacLength = 32;
    private const int Sha512MacLength = 64;
    private const int GcmIvLength = 12;
    private const int CtrIvLength = 16;

    /// <summary>
    /// Creates the cipher for one direction.
    /// </summary>
    /// <param name="cipherName">The negotiated encryption algorithm name.</param>
    /// <param name="macName">The negotiated MAC algorithm name (ignored for AEAD ciphers).</param>
    /// <param name="encryptionKey">The direction's derived encryption key (64 bytes; a prefix is used).</param>
    /// <param name="iv">The direction's derived initial IV (64 bytes; a prefix is used).</param>
    /// <param name="integrityKey">The direction's derived integrity key (64 bytes; a prefix is used for HMAC modes).</param>
    /// <returns>The cipher for the direction.</returns>
    /// <exception cref="SshKeyExchangeException">The cipher or MAC name is not supported.</exception>
    public static ISshPacketCipher Create(
        string cipherName,
        string macName,
        ReadOnlySpan<byte> encryptionKey,
        ReadOnlySpan<byte> iv,
        ReadOnlySpan<byte> integrityKey)
    {
        ArgumentNullException.ThrowIfNull(cipherName);
        ArgumentNullException.ThrowIfNull(macName);

        switch (cipherName)
        {
            case SshAlgorithmNames.ChaCha20Poly1305:
                return new ChaCha20Poly1305Cipher(encryptionKey.Slice(0, ChaCha20Poly1305Cipher.KeyLength));
            case SshAlgorithmNames.Aes256Gcm:
                return new AesGcmCipher(encryptionKey.Slice(0, 32), iv.Slice(0, GcmIvLength));
            case SshAlgorithmNames.Aes128Gcm:
                return new AesGcmCipher(encryptionKey.Slice(0, 16), iv.Slice(0, GcmIvLength));
            case SshAlgorithmNames.Aes256Ctr:
                return CreateCtr(encryptionKey.Slice(0, 32), iv, integrityKey, macName);
            case SshAlgorithmNames.Aes128Ctr:
                return CreateCtr(encryptionKey.Slice(0, 16), iv, integrityKey, macName);
            default:
                throw new SshKeyExchangeException($"Unsupported encryption algorithm '{cipherName}'.");
        }
    }

    private static AesCtrCipher CreateCtr(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> integrityKey, string macName)
    {
        switch (macName)
        {
            case SshAlgorithmNames.HmacSha2256:
                return new AesCtrCipher(key, iv.Slice(0, CtrIvLength), integrityKey.Slice(0, Sha256MacKeyLength), HashAlgorithmName.SHA256, Sha256MacLength);
            case SshAlgorithmNames.HmacSha2512:
                return new AesCtrCipher(key, iv.Slice(0, CtrIvLength), integrityKey.Slice(0, Sha512MacKeyLength), HashAlgorithmName.SHA512, Sha512MacLength);
            default:
                throw new SshKeyExchangeException($"Unsupported MAC algorithm '{macName}' for a counter-mode cipher.");
        }
    }
}
