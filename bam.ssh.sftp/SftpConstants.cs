namespace Bam.Ssh.Sftp;

/// <summary>
/// Protocol constants for SFTP version 3: the negotiated version, the ATTRS presence-flag bits, and the
/// POSIX mode bits used to distinguish files from directories and to default permissions.
/// </summary>
public static class SftpConstants
{
    /// <summary>The SFTP protocol version this implementation speaks (the OpenSSH-compatible v3).</summary>
    public const uint Version = 3;

    /// <summary>ATTRS flag: the size field is present.</summary>
    public const uint AttrSize = 0x00000001;

    /// <summary>ATTRS flag: the uid and gid fields are present.</summary>
    public const uint AttrUidGid = 0x00000002;

    /// <summary>ATTRS flag: the permissions field is present.</summary>
    public const uint AttrPermissions = 0x00000004;

    /// <summary>ATTRS flag: the atime and mtime fields are present.</summary>
    public const uint AttrAccessModifyTime = 0x00000008;

    /// <summary>ATTRS flag: extended attribute pairs are present.</summary>
    public const uint AttrExtended = 0x80000000;

    /// <summary>POSIX mode mask selecting the file-type bits.</summary>
    public const uint ModeFormatMask = 0xF000;

    /// <summary>POSIX mode bits for a directory.</summary>
    public const uint ModeDirectory = 0x4000;

    /// <summary>POSIX mode bits for a regular file.</summary>
    public const uint ModeRegularFile = 0x8000;

    /// <summary>POSIX mode bits for a symbolic link.</summary>
    public const uint ModeSymbolicLink = 0xA000;

    /// <summary>Default permission bits for a new regular file (0644).</summary>
    public const uint DefaultFilePermissions = 0x1A4;

    /// <summary>Default permission bits for a new directory (0755).</summary>
    public const uint DefaultDirectoryPermissions = 0x1ED;
}
