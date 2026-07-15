namespace Bam.Ssh;

/// <summary>
/// Thrown when an RFC 4253 §6 binary packet frame violates the protocol's structural rules —
/// an out-of-range packet length, an invalid padding length, or arithmetic that would overflow.
/// Carries the <see cref="SshDisconnectReason"/> the transport layer should use when it
/// subsequently emits an SSH_MSG_DISCONNECT for this violation.
/// </summary>
public sealed class SshPacketFormatException : SshException
{
    /// <summary>
    /// Gets the RFC 4250 disconnect reason associated with this framing violation.
    /// The transport layer uses this value when sending SSH_MSG_DISCONNECT to the peer.
    /// </summary>
    public SshDisconnectReason Reason { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="SshPacketFormatException"/> class with the
    /// specified message and disconnect reason.
    /// </summary>
    /// <param name="message">A description of the framing violation.</param>
    /// <param name="reason">The RFC 4250 disconnect reason the transport should report to the peer.</param>
    public SshPacketFormatException(string message, SshDisconnectReason reason) : base(message)
    {
        Reason = reason;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SshPacketFormatException"/> class with the
    /// specified message, disconnect reason, and inner exception.
    /// </summary>
    /// <param name="message">A description of the framing violation.</param>
    /// <param name="reason">The RFC 4250 disconnect reason the transport should report to the peer.</param>
    /// <param name="innerException">The exception that caused this failure.</param>
    public SshPacketFormatException(string message, SshDisconnectReason reason, Exception innerException)
        : base(message, innerException)
    {
        Reason = reason;
    }
}
