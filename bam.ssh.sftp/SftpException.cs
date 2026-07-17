namespace Bam.Ssh.Sftp;

/// <summary>
/// The base exception for SFTP protocol failures — a malformed message, an unexpected response, or a
/// broken subsystem stream. A server-reported error status surfaces as the derived
/// <see cref="SftpStatusException"/>.
/// </summary>
public class SftpException : SshException
{
    /// <summary>
    /// Initializes the exception with a message.
    /// </summary>
    /// <param name="message">The error message.</param>
    public SftpException(string message)
        : base(message)
    {
    }

    /// <summary>
    /// Initializes the exception with a message and inner exception.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The underlying cause.</param>
    public SftpException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
