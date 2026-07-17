namespace Bam.Ssh.Sftp;

/// <summary>
/// Thrown when the SFTP server returns an error <see cref="SftpPacketType.Status"/> for a request (any code
/// other than <see cref="SftpStatusCode.Ok"/> or, where it is an expected terminator,
/// <see cref="SftpStatusCode.Eof"/>). Carries the status code so callers can branch on, for example,
/// <see cref="SftpStatusCode.NoSuchFile"/>. Server-side filesystem code throws this to map a failure to a
/// specific status the engine returns to the peer.
/// </summary>
public sealed class SftpStatusException : SftpException
{
    /// <summary>
    /// Initializes the exception with a status code and message.
    /// </summary>
    /// <param name="statusCode">The SFTP status code.</param>
    /// <param name="message">The error message.</param>
    public SftpStatusException(SftpStatusCode statusCode, string message)
        : base(message)
    {
        StatusCode = statusCode;
    }

    /// <summary>Gets the SFTP status code the server reported.</summary>
    public SftpStatusCode StatusCode { get; }
}
