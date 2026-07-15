namespace Bam.Ssh;

/// <summary>
/// Thrown when a malformed RFC 4251 primitive is encountered while decoding wire data —
/// for example a truncated field, a length prefix that exceeds the available bytes,
/// a non-minimally-encoded mpint, or an invalid name-list. Indicates the peer (or a test input)
/// violated the SSH wire encoding rules; the data cannot be safely interpreted.
/// </summary>
public sealed class SshWireFormatException : SshException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="SshWireFormatException"/> class.
    /// </summary>
    public SshWireFormatException()
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SshWireFormatException"/> class with the specified message.
    /// </summary>
    /// <param name="message">A description of the encoding violation.</param>
    public SshWireFormatException(string message) : base(message)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SshWireFormatException"/> class with the specified
    /// message and inner exception.
    /// </summary>
    /// <param name="message">A description of the encoding violation.</param>
    /// <param name="innerException">The exception that caused this failure.</param>
    public SshWireFormatException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
