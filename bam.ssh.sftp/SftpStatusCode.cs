namespace Bam.Ssh.Sftp;

/// <summary>
/// SFTP status codes (SSH_FX_*) carried by an <see cref="SftpPacketType.Status"/> response. <see cref="Ok"/>
/// signals success; <see cref="Eof"/> ends a read or directory listing; the rest are failures a client
/// surfaces as an <c>SftpStatusException</c>.
/// </summary>
public enum SftpStatusCode : uint
{
    /// <summary>The operation succeeded.</summary>
    Ok = 0,

    /// <summary>End of file, or no more directory entries.</summary>
    Eof = 1,

    /// <summary>The referenced file or directory does not exist.</summary>
    NoSuchFile = 2,

    /// <summary>The caller lacks permission for the operation.</summary>
    PermissionDenied = 3,

    /// <summary>A general failure.</summary>
    Failure = 4,

    /// <summary>A badly formatted or unexpected message.</summary>
    BadMessage = 5,

    /// <summary>No connection to the server (client-side only).</summary>
    NoConnection = 6,

    /// <summary>The connection to the server was lost (client-side only).</summary>
    ConnectionLost = 7,

    /// <summary>The operation is not supported by the server.</summary>
    OperationUnsupported = 8,
}
