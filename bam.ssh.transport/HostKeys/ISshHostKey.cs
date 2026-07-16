namespace Bam.Ssh.Transport;

/// <summary>
/// A parsed server host public key that verifies a signature over the exchange hash. Produced by
/// <see cref="SshHostKeyParser"/> from the K_S blob a server sends in its key-exchange reply. This
/// type only proves a signature is cryptographically valid; deciding whether the key should be
/// <em>trusted</em> (known_hosts / TOFU) is a higher-layer concern (Phase 7 client).
/// </summary>
public interface ISshHostKey
{
    /// <summary>Gets the host-key algorithm name (e.g. <c>ssh-ed25519</c>, <c>ssh-rsa</c>).</summary>
    string Algorithm { get; }

    /// <summary>Gets the raw K_S host-key blob as received on the wire.</summary>
    ReadOnlyMemory<byte> KeyBlob { get; }

    /// <summary>
    /// Gets the OpenSSH-style key fingerprint (<c>SHA256:base64</c> of the key blob, no padding),
    /// suitable for display and known_hosts comparison.
    /// </summary>
    string Fingerprint { get; }

    /// <summary>
    /// Verifies a server signature over the given hash.
    /// </summary>
    /// <param name="hash">The exchange hash H the signature is expected to cover.</param>
    /// <param name="signatureBlob">The SSH signature blob (<c>string(algorithm) || string(signature)</c>).</param>
    /// <returns>True when the signature verifies against this host key.</returns>
    bool Verify(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signatureBlob);
}
