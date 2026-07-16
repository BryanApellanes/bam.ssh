namespace Bam.Ssh.Transport;

/// <summary>
/// The outcome of a successful key exchange: the negotiated algorithms, the verified server host
/// key, the exchange hash H, the session identifier, and the derived directional key material.
/// Phase 4 turns <see cref="SessionKeys"/> into live ciphers/MACs and installs them via
/// <see cref="SshTransport.ApplyKeys"/>; Phase 7 applies host-key trust policy to <see cref="HostKey"/>.
/// </summary>
public sealed class SshKeyExchangeResult
{
    /// <summary>
    /// Initializes a key-exchange result.
    /// </summary>
    /// <param name="algorithms">The negotiated algorithms.</param>
    /// <param name="hostKey">The verified server host key.</param>
    /// <param name="exchangeHash">The exchange hash H for this exchange.</param>
    /// <param name="sessionKeys">The derived key material and session id.</param>
    public SshKeyExchangeResult(
        SshNegotiatedAlgorithms algorithms,
        ISshHostKey hostKey,
        byte[] exchangeHash,
        SshSessionKeys sessionKeys)
    {
        Algorithms = algorithms;
        HostKey = hostKey;
        ExchangeHash = exchangeHash;
        SessionKeys = sessionKeys;
    }

    /// <summary>Gets the algorithms negotiated for the session.</summary>
    public SshNegotiatedAlgorithms Algorithms { get; }

    /// <summary>Gets the verified server host key (signature-valid; trust is a higher-layer decision).</summary>
    public ISshHostKey HostKey { get; }

    /// <summary>Gets the exchange hash H produced by this key exchange.</summary>
    public byte[] ExchangeHash { get; }

    /// <summary>Gets the derived key material and session identifier.</summary>
    public SshSessionKeys SessionKeys { get; }
}
