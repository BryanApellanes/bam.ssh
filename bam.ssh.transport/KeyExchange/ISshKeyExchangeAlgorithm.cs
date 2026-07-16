using System.Security.Cryptography;

namespace Bam.Ssh.Transport;

/// <summary>
/// One key-agreement method (curve25519-sha256, ecdh-sha2-nistp256, diffie-hellman-group14-sha256).
/// The client generates an ephemeral key pair, publishes its public value, receives the peer's, and
/// derives the shared secret. An instance is single-use per exchange (it holds the ephemeral private
/// key) and is not thread-safe. The type is role-agnostic: the future server uses the same agreement
/// by swapping which value it sends versus receives.
/// </summary>
public interface ISshKeyExchangeAlgorithm
{
    /// <summary>Gets the wire name of this method (e.g. <c>curve25519-sha256</c>).</summary>
    string Name { get; }

    /// <summary>Gets the hash algorithm used for the exchange hash and key derivation (SHA-256 for all required methods).</summary>
    HashAlgorithmName HashAlgorithm { get; }

    /// <summary>Gets how this method's public values are encoded in the exchange hash.</summary>
    SshKeyExchangePublicValueFormat PublicValueFormat { get; }

    /// <summary>
    /// Generates the ephemeral key pair and returns this side's public value in its raw wire form
    /// (an EC point / X25519 key for string-format methods; the big-endian magnitude of <c>e</c> for
    /// DH). Call once; the ephemeral private key is retained for <see cref="DeriveSharedSecret"/>.
    /// </summary>
    /// <returns>The raw public-value bytes to send to the peer.</returns>
    byte[] CreateClientPublicValue();

    /// <summary>
    /// Derives the shared secret from the peer's public value, as an unsigned big-endian magnitude
    /// ready to be encoded as an mpint (K).
    /// </summary>
    /// <param name="peerPublicValue">The peer's raw public value.</param>
    /// <returns>The shared secret as an unsigned big-endian magnitude.</returns>
    /// <exception cref="SshKeyExchangeException">The peer's public value is invalid for this method.</exception>
    byte[] DeriveSharedSecret(ReadOnlySpan<byte> peerPublicValue);
}
