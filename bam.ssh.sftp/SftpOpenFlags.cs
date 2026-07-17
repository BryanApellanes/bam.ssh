namespace Bam.Ssh.Sftp;

/// <summary>
/// The file-open flags (SSH_FXF_*) carried by an <see cref="SftpPacketType.Open"/> request (RFC
/// draft-ietf-secsh-filexfer-02 §6.3). Combine with a bitwise OR.
/// </summary>
[Flags]
public enum SftpOpenFlags : uint
{
    /// <summary>No flags.</summary>
    None = 0x00000000,

    /// <summary>Open for reading.</summary>
    Read = 0x00000001,

    /// <summary>Open for writing.</summary>
    Write = 0x00000002,

    /// <summary>Append writes to the end of the file.</summary>
    Append = 0x00000004,

    /// <summary>Create the file if it does not exist.</summary>
    Create = 0x00000008,

    /// <summary>Truncate the file to zero length on open.</summary>
    Truncate = 0x00000010,

    /// <summary>Fail if the file already exists (with <see cref="Create"/>).</summary>
    Exclusive = 0x00000020,
}
