namespace Bam.Ssh.Authentication;

/// <summary>
/// Raised when user authentication fails at the protocol level: the <c>ssh-userauth</c> service was
/// refused, an authentication reply was malformed, a private-key file could not be parsed, or an
/// unsupported key form was encountered. This signals a hard error in the authentication exchange —
/// distinct from an ordinary authentication <em>rejection</em> (a well-formed
/// SSH_MSG_USERAUTH_FAILURE), which is reported through <see cref="SshAuthenticationResult"/> rather
/// than thrown.
/// </summary>
public sealed class SshAuthenticationException : SshException
{
    /// <summary>
    /// Initializes a new instance with the specified message.
    /// </summary>
    /// <param name="message">A description of the failure.</param>
    public SshAuthenticationException(string message) : base(message)
    {
    }

    /// <summary>
    /// Initializes a new instance with the specified message and inner exception.
    /// </summary>
    /// <param name="message">A description of the failure.</param>
    /// <param name="innerException">The exception that caused this failure.</param>
    public SshAuthenticationException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
