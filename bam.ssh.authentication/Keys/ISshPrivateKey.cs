namespace Bam.Ssh.Authentication;

/// <summary>
/// A client private key that signs the session-bound authentication blob for publickey authentication
/// (RFC 4252 §7). This is the signing counterpart to the transport's <c>ISshHostKey</c> (which only
/// verifies): the public-key blob and signature blob produced here use the identical
/// <c>string(algorithm) || string(signature)</c> wire encoding a server verifies, so a signature from
/// this type is accepted by the matching transport host-key verifier.
/// </summary>
public interface ISshPrivateKey
{
    /// <summary>
    /// Gets the public-key algorithm name as it appears in the authentication request and signature
    /// blob (e.g. <c>ssh-ed25519</c>, <c>ecdsa-sha2-nistp256</c>, <c>rsa-sha2-256</c>).
    /// </summary>
    string Algorithm { get; }

    /// <summary>
    /// Gets the public-key blob (the same K_S-style encoding a host key transmits) that identifies
    /// this key in the SSH_MSG_USERAUTH_REQUEST.
    /// </summary>
    ReadOnlyMemory<byte> PublicKeyBlob { get; }

    /// <summary>
    /// Signs the given data and returns the SSH signature blob
    /// (<c>string(algorithm) || string(signature)</c>).
    /// </summary>
    /// <param name="data">The bytes to sign (for publickey auth, the session-id-bound request blob).</param>
    /// <returns>The encoded SSH signature blob.</returns>
    byte[] Sign(ReadOnlySpan<byte> data);
}
