namespace Bam.Ssh.Transport;

/// <summary>
/// Re-runs key exchange on an established connection (RFC 4253 §9), preserving the original session
/// identifier and activating fresh ciphers. Implemented by both <see cref="SshClientKeyExchange"/> and
/// <see cref="SshServerKeyExchange"/> so the connection layer can drive a re-key regardless of role,
/// feeding key-exchange packets from its receive loop through the supplied <see cref="ISshPacketSource"/>.
/// </summary>
public interface ISshRekeyDriver
{
    /// <summary>
    /// Re-keys the connection.
    /// </summary>
    /// <param name="sessionId">The session identifier established by the first exchange.</param>
    /// <param name="packetSource">The source of inbound key-exchange packets, or null to read the transport directly.</param>
    /// <param name="cancellationToken">Cancels the exchange.</param>
    /// <returns>The renegotiated algorithms, host key, and freshly derived session keys.</returns>
    ValueTask<SshKeyExchangeResult> RekeyAsync(byte[] sessionId, ISshPacketSource? packetSource = null, CancellationToken cancellationToken = default);
}
