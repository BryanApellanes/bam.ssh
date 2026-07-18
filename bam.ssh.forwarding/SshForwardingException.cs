namespace Bam.Ssh.Forwarding;

/// <summary>
/// The exception for TCP/IP forwarding failures — a malformed <c>direct-tcpip</c>/<c>forwarded-tcpip</c>
/// channel record, an unparseable <c>tcpip-forward</c> request or reply, a refused forwarding request, or a
/// SOCKS negotiation error.
/// </summary>
public class SshForwardingException : SshException
{
    /// <summary>
    /// Initializes the exception with a message.
    /// </summary>
    /// <param name="message">The error message.</param>
    public SshForwardingException(string message)
        : base(message)
    {
    }

    /// <summary>
    /// Initializes the exception with a message and inner exception.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The underlying cause.</param>
    public SshForwardingException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
