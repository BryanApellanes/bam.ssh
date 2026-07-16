namespace Bam.Ssh.Transport;

/// <summary>
/// Raised when key exchange fails: no common algorithm was found, a reply was malformed, the host
/// key could not be parsed, or — most importantly — the host-key signature over the exchange hash
/// did not verify. A failed signature verification is a hard rejection: the connection must not
/// proceed. Defaults the disconnect reason to <see cref="SshDisconnectReason.KeyExchangeFailed"/>.
/// </summary>
public sealed class SshKeyExchangeException : SshTransportException
{
    /// <summary>
    /// Initializes a new instance with a message and the key-exchange-failed reason.
    /// </summary>
    /// <param name="message">A description of the failure.</param>
    public SshKeyExchangeException(string message)
        : base(message, SshDisconnectReason.KeyExchangeFailed)
    {
    }

    /// <summary>
    /// Initializes a new instance with a message and an explicit disconnect reason.
    /// </summary>
    /// <param name="message">A description of the failure.</param>
    /// <param name="reason">The disconnect reason to report.</param>
    public SshKeyExchangeException(string message, SshDisconnectReason reason)
        : base(message, reason)
    {
    }

    /// <summary>
    /// Initializes a new instance with a message, reason, and inner exception.
    /// </summary>
    /// <param name="message">A description of the failure.</param>
    /// <param name="reason">The disconnect reason to report.</param>
    /// <param name="innerException">The exception that caused this failure.</param>
    public SshKeyExchangeException(string message, SshDisconnectReason reason, Exception innerException)
        : base(message, reason, innerException)
    {
    }
}
