namespace Bam.Ssh.Transport;

/// <summary>
/// Parses a server host-key blob (K_S) into the appropriate <see cref="ISshHostKey"/> by reading its
/// leading algorithm-name string. Supports ssh-ed25519, ecdsa-sha2-nistp256, and ssh-rsa (verified
/// with rsa-sha2-256/512). Unknown key types are rejected.
/// </summary>
public static class SshHostKeyParser
{
    /// <summary>
    /// Parses a host-key blob into a verifiable host key.
    /// </summary>
    /// <param name="keyBlob">The K_S blob from the key-exchange reply.</param>
    /// <returns>The parsed host key.</returns>
    /// <exception cref="SshKeyExchangeException">The blob is malformed or names an unsupported key type.</exception>
    public static ISshHostKey Parse(ReadOnlySpan<byte> keyBlob)
    {
        byte[] blobCopy = keyBlob.ToArray();
        SshWireReader reader = new SshWireReader(blobCopy);
        string algorithm;
        try
        {
            algorithm = reader.ReadText();
        }
        catch (SshWireFormatException exception)
        {
            throw new SshKeyExchangeException("The host key blob was empty or malformed.", SshDisconnectReason.KeyExchangeFailed, exception);
        }

        switch (algorithm)
        {
            case SshAlgorithmNames.SshEd25519:
                return Ed25519HostKey.Parse(blobCopy, ref reader);
            case SshAlgorithmNames.EcdsaSha2Nistp256:
                return EcdsaNistP256HostKey.Parse(blobCopy, ref reader);
            case SshAlgorithmNames.SshRsaKeyType:
                return RsaHostKey.Parse(blobCopy, ref reader);
            default:
                throw new SshKeyExchangeException($"Unsupported host key algorithm '{algorithm}'.");
        }
    }
}
