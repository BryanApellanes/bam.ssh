namespace Bam.Ssh.Connection;

/// <summary>
/// A channel-scoped failure: an operation on a channel that has been closed, a window-accounting
/// violation, a malformed channel message, or a rejected channel open. Distinct from
/// <see cref="SshConnectionException"/>, which covers failures of the shared connection itself.
/// </summary>
public sealed class SshChannelException : SshException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="SshChannelException"/> class with a message.
    /// </summary>
    /// <param name="message">A description of the failure.</param>
    public SshChannelException(string message) : base(message)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SshChannelException"/> class with a message and an
    /// inner exception.
    /// </summary>
    /// <param name="message">A description of the failure.</param>
    /// <param name="innerException">The exception that caused this failure.</param>
    public SshChannelException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
