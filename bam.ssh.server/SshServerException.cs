namespace Bam.Ssh.Server;

/// <summary>
/// Thrown when the SSH server cannot accept, key, authenticate, or serve a peer connection because of a
/// server-side configuration or protocol error (for example, no host key was added before starting, or the
/// listener could not bind). Per-channel and per-command failures are reported to the peer through the
/// connection protocol rather than raised as this exception.
/// </summary>
public sealed class SshServerException : SshException
{
    /// <summary>
    /// Initializes the exception with a message.
    /// </summary>
    /// <param name="message">The error message.</param>
    public SshServerException(string message)
        : base(message)
    {
    }

    /// <summary>
    /// Initializes the exception with a message and inner exception.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The underlying cause.</param>
    public SshServerException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
