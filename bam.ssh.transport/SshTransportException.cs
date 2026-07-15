namespace Bam.Ssh.Transport;

/// <summary>
/// A transport-layer protocol failure: a malformed identification string, an unexpected
/// end-of-stream during the handshake, or a framing violation surfaced from the packet layer.
/// Carries the <see cref="SshDisconnectReason"/> that should accompany an SSH_MSG_DISCONNECT.
/// </summary>
public class SshTransportException : SshException
{
    /// <summary>
    /// Gets the disconnect reason associated with this transport failure.
    /// </summary>
    public SshDisconnectReason Reason { get; }

    /// <summary>
    /// Initializes a new instance with a message and disconnect reason.
    /// </summary>
    /// <param name="message">A description of the failure.</param>
    /// <param name="reason">The disconnect reason to report.</param>
    public SshTransportException(string message, SshDisconnectReason reason) : base(message)
    {
        Reason = reason;
    }

    /// <summary>
    /// Initializes a new instance with a message, disconnect reason, and inner exception.
    /// </summary>
    /// <param name="message">A description of the failure.</param>
    /// <param name="reason">The disconnect reason to report.</param>
    /// <param name="innerException">The exception that caused this failure.</param>
    public SshTransportException(string message, SshDisconnectReason reason, Exception innerException)
        : base(message, innerException)
    {
        Reason = reason;
    }
}
