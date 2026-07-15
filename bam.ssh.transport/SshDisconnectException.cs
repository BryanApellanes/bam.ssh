namespace Bam.Ssh.Transport;

/// <summary>
/// Raised when an SSH_MSG_DISCONNECT message is received from the peer (or surfaced locally when
/// this side initiates a disconnect). Distinguished from a general <see cref="SshTransportException"/>
/// so callers can tell an orderly protocol shutdown from a transport fault, and carries the peer's
/// human-readable description alongside the reason code.
/// </summary>
public sealed class SshDisconnectException : SshTransportException
{
    /// <summary>
    /// Initializes a new instance from a received SSH_MSG_DISCONNECT.
    /// </summary>
    /// <param name="reason">The disconnect reason code the peer sent.</param>
    /// <param name="description">The peer's human-readable description (may be empty).</param>
    public SshDisconnectException(SshDisconnectReason reason, string description)
        : base($"The peer disconnected: {reason} ({description}).", reason)
    {
        Description = description;
    }

    /// <summary>
    /// Gets the human-readable description carried by the SSH_MSG_DISCONNECT message.
    /// </summary>
    public string Description { get; }
}
