namespace Bam.Ssh.Scp;

/// <summary>
/// The exception for SCP protocol failures — a malformed control record, an unparseable <c>scp</c> command
/// line, an unexpected end of stream, or an error record (<c>0x01</c>/<c>0x02</c>) the peer sent in place of
/// an acknowledgement.
/// </summary>
public class ScpException : SshException
{
    /// <summary>
    /// Initializes the exception with a message.
    /// </summary>
    /// <param name="message">The error message.</param>
    public ScpException(string message)
        : base(message)
    {
    }

    /// <summary>
    /// Initializes the exception with a message and inner exception.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The underlying cause.</param>
    public ScpException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
