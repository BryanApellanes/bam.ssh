namespace Bam.Ssh.Transport;

/// <summary>
/// Creates the <see cref="ISshKeyExchangeAlgorithm"/> implementation for a negotiated method name,
/// mapping the OpenSSH curve25519 alias onto the standard method. Unknown names are rejected — the
/// name should always be one that negotiation selected from the local catalog.
/// </summary>
public static class SshKeyExchangeAlgorithmFactory
{
    /// <summary>
    /// Creates a key-exchange algorithm for the negotiated method name.
    /// </summary>
    /// <param name="algorithmName">The negotiated key-exchange algorithm name.</param>
    /// <param name="random">The randomness source for ephemeral keys; defaults to <see cref="SecureSshRandom.Instance"/>.</param>
    /// <returns>A single-use algorithm instance.</returns>
    /// <exception cref="SshKeyExchangeException">The name is not a supported key-exchange method.</exception>
    public static ISshKeyExchangeAlgorithm Create(string algorithmName, ISshRandom? random = null)
    {
        switch (algorithmName)
        {
            case SshAlgorithmNames.Curve25519Sha256:
            case SshAlgorithmNames.Curve25519Sha256LibsshAlias:
                return new Curve25519KeyExchange(random);
            case SshAlgorithmNames.EcdhSha2Nistp256:
                return new EcdhNistP256KeyExchange();
            case SshAlgorithmNames.DhGroup14Sha256:
                return new DiffieHellmanGroup14KeyExchange(random);
            default:
                throw new SshKeyExchangeException($"Unsupported key-exchange algorithm '{algorithmName}'.");
        }
    }
}
