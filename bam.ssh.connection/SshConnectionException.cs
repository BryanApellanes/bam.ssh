namespace Bam.Ssh.Connection;

/// <summary>
/// A connection-protocol (RFC 4254) failure that is not specific to a single channel — for example a
/// malformed connection-level message, an unexpected recipient channel id, or a protocol-ordering
/// violation on the multiplexed transport.
/// </summary>
public sealed class SshConnectionException : SshException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="SshConnectionException"/> class with a message.
    /// </summary>
    /// <param name="message">A description of the failure.</param>
    public SshConnectionException(string message) : base(message)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SshConnectionException"/> class with a message and
    /// an inner exception.
    /// </summary>
    /// <param name="message">A description of the failure.</param>
    /// <param name="innerException">The exception that caused this failure.</param>
    public SshConnectionException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
