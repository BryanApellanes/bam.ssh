namespace Bam.Ssh.Sftp;

/// <summary>
/// SFTP protocol message numbers (draft-ietf-secsh-filexfer-02, the version-3 wire OpenSSH speaks). The
/// request types (1–20) are sent by the client; the response types (101–105) by the server; the extended
/// pair (200/201) carries vendor extensions this implementation answers <c>OP_UNSUPPORTED</c>.
/// </summary>
public enum SftpPacketType : byte
{
    /// <summary>Client → server: begins the session, carries the client's version.</summary>
    Init = 1,

    /// <summary>Server → client: the negotiated version and server extensions.</summary>
    Version = 2,

    /// <summary>Open (or create) a file, returning a handle.</summary>
    Open = 3,

    /// <summary>Close an open file or directory handle.</summary>
    Close = 4,

    /// <summary>Read bytes from an open file at an offset.</summary>
    Read = 5,

    /// <summary>Write bytes to an open file at an offset.</summary>
    Write = 6,

    /// <summary>Stat a path, following symbolic links.</summary>
    LStat = 7,

    /// <summary>Stat an open file handle.</summary>
    FStat = 8,

    /// <summary>Set attributes on a path.</summary>
    SetStat = 9,

    /// <summary>Set attributes on an open file handle.</summary>
    FSetStat = 10,

    /// <summary>Open a directory for listing, returning a handle.</summary>
    OpenDir = 11,

    /// <summary>Read the next batch of directory entries.</summary>
    ReadDir = 12,

    /// <summary>Remove a file.</summary>
    Remove = 13,

    /// <summary>Create a directory.</summary>
    MkDir = 14,

    /// <summary>Remove a directory.</summary>
    RmDir = 15,

    /// <summary>Canonicalize a path.</summary>
    RealPath = 16,

    /// <summary>Stat a path without following symbolic links.</summary>
    Stat = 17,

    /// <summary>Rename a file or directory.</summary>
    Rename = 18,

    /// <summary>Read the target of a symbolic link.</summary>
    ReadLink = 19,

    /// <summary>Create a symbolic link.</summary>
    Symlink = 20,

    /// <summary>Server → client: a status/result code with a message.</summary>
    Status = 101,

    /// <summary>Server → client: an opaque file or directory handle.</summary>
    Handle = 102,

    /// <summary>Server → client: file data.</summary>
    Data = 103,

    /// <summary>Server → client: a list of names (directory entries or a canonical path).</summary>
    Name = 104,

    /// <summary>Server → client: file attributes.</summary>
    Attrs = 105,

    /// <summary>Client → server: a vendor extension request.</summary>
    Extended = 200,

    /// <summary>Server → client: a vendor extension reply.</summary>
    ExtendedReply = 201,
}
