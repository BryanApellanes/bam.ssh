namespace Bam.Ssh;

/// <summary>
/// The root exception type for the bam.ssh stack. Every exception thrown by bam.ssh libraries
/// derives from this type so callers can catch protocol-stack failures with a single filter
/// while still distinguishing more specific failures such as <see cref="SshWireFormatException"/>
/// and <see cref="SshPacketFormatException"/>.
/// </summary>
public class SshException : Exception
{
    /// <summary>
    /// Initializes a new instance of the <see cref="SshException"/> class.
    /// </summary>
    public SshException()
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SshException"/> class with the specified message.
    /// </summary>
    /// <param name="message">A description of the failure.</param>
    public SshException(string message) : base(message)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SshException"/> class with the specified message
    /// and inner exception.
    /// </summary>
    /// <param name="message">A description of the failure.</param>
    /// <param name="innerException">The exception that caused this failure.</param>
    public SshException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
