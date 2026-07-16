namespace Bam.Ssh.Transport;

/// <summary>
/// A server host key that can <em>sign</em> the key-exchange hash — the signing peer of the verify-only
/// <see cref="ISshHostKey"/>. The public-key blob is the K_S a server sends in its key-exchange reply,
/// and <see cref="Sign"/> returns the SSH signature blob (<c>string(algorithm) || string(signature)</c>)
/// a client verifies with the matching <see cref="ISshHostKey"/>. The Phase 5 client private keys already
/// have this exact shape, so they double as host keys without duplication.
/// </summary>
public interface ISshHostKeySigner
{
    /// <summary>
    /// Gets the host-key algorithm name (e.g. <c>ssh-ed25519</c>, <c>rsa-sha2-256</c>).
    /// </summary>
    string Algorithm { get; }

    /// <summary>
    /// Gets the public host-key blob (K_S) transmitted in the key-exchange reply.
    /// </summary>
    ReadOnlyMemory<byte> PublicKeyBlob { get; }

    /// <summary>
    /// Signs the given data (the exchange hash) and returns the SSH signature blob.
    /// </summary>
    /// <param name="data">The bytes to sign.</param>
    /// <returns>The encoded SSH signature blob.</returns>
    byte[] Sign(ReadOnlySpan<byte> data);
}
