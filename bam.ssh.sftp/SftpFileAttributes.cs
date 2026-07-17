namespace Bam.Ssh.Sftp;

/// <summary>
/// The SFTP ATTRS structure (draft-ietf-secsh-filexfer-02 §5): a presence-flag word followed by only the
/// fields whose flags are set — size, uid/gid, permissions (POSIX mode bits), and access/modify times.
/// Fields not present read back as null, so a client can tell "not reported" from "zero".
/// </summary>
public sealed class SftpFileAttributes
{
    /// <summary>
    /// Initializes an attribute set. Pass null for any field the server does not report; the presence flags
    /// are derived from which fields are non-null.
    /// </summary>
    /// <param name="size">The file size in bytes, or null.</param>
    /// <param name="userId">The owning user id, or null.</param>
    /// <param name="groupId">The owning group id, or null.</param>
    /// <param name="permissions">The POSIX mode bits (type + permission bits), or null.</param>
    /// <param name="accessTime">The last-access time (Unix seconds), or null.</param>
    /// <param name="modifyTime">The last-modify time (Unix seconds), or null.</param>
    public SftpFileAttributes(
        ulong? size = null,
        uint? userId = null,
        uint? groupId = null,
        uint? permissions = null,
        uint? accessTime = null,
        uint? modifyTime = null)
    {
        Size = size;
        UserId = userId;
        GroupId = groupId;
        Permissions = permissions;
        AccessTime = accessTime;
        ModifyTime = modifyTime;
    }

    /// <summary>Gets the file size in bytes, or null when not reported.</summary>
    public ulong? Size { get; }

    /// <summary>Gets the owning user id, or null when not reported.</summary>
    public uint? UserId { get; }

    /// <summary>Gets the owning group id, or null when not reported.</summary>
    public uint? GroupId { get; }

    /// <summary>Gets the POSIX mode bits (file type in the high bits, permission bits in the low), or null.</summary>
    public uint? Permissions { get; }

    /// <summary>Gets the last-access time in Unix seconds, or null when not reported.</summary>
    public uint? AccessTime { get; }

    /// <summary>Gets the last-modify time in Unix seconds, or null when not reported.</summary>
    public uint? ModifyTime { get; }

    /// <summary>
    /// Gets whether the permission bits mark this as a directory. False when permissions are absent.
    /// </summary>
    public bool IsDirectory => Permissions is uint mode && (mode & SftpConstants.ModeFormatMask) == SftpConstants.ModeDirectory;

    /// <summary>
    /// Gets whether the permission bits mark this as a symbolic link. False when permissions are absent.
    /// </summary>
    public bool IsSymbolicLink => Permissions is uint mode && (mode & SftpConstants.ModeFormatMask) == SftpConstants.ModeSymbolicLink;

    /// <summary>
    /// Reads an ATTRS structure from the wire.
    /// </summary>
    /// <param name="reader">The wire reader positioned at the flags word.</param>
    /// <returns>The parsed attributes.</returns>
    public static SftpFileAttributes ReadFrom(ref SshWireReader reader)
    {
        uint flags = reader.ReadUInt32();
        ulong? size = (flags & SftpConstants.AttrSize) != 0 ? reader.ReadUInt64() : null;
        uint? userId = null;
        uint? groupId = null;
        if ((flags & SftpConstants.AttrUidGid) != 0)
        {
            userId = reader.ReadUInt32();
            groupId = reader.ReadUInt32();
        }
        uint? permissions = (flags & SftpConstants.AttrPermissions) != 0 ? reader.ReadUInt32() : null;
        uint? accessTime = null;
        uint? modifyTime = null;
        if ((flags & SftpConstants.AttrAccessModifyTime) != 0)
        {
            accessTime = reader.ReadUInt32();
            modifyTime = reader.ReadUInt32();
        }
        if ((flags & SftpConstants.AttrExtended) != 0)
        {
            uint count = reader.ReadUInt32();
            for (uint i = 0; i < count; i++)
            {
                reader.ReadString();
                reader.ReadString();
            }
        }
        return new SftpFileAttributes(size, userId, groupId, permissions, accessTime, modifyTime);
    }

    /// <summary>
    /// Writes this ATTRS structure to the wire, emitting the presence flags and only the present fields.
    /// </summary>
    /// <param name="writer">The wire writer.</param>
    public void WriteTo(ref SshWireWriter writer)
    {
        uint flags = 0;
        if (Size.HasValue)
        {
            flags |= SftpConstants.AttrSize;
        }
        if (UserId.HasValue && GroupId.HasValue)
        {
            flags |= SftpConstants.AttrUidGid;
        }
        if (Permissions.HasValue)
        {
            flags |= SftpConstants.AttrPermissions;
        }
        if (AccessTime.HasValue && ModifyTime.HasValue)
        {
            flags |= SftpConstants.AttrAccessModifyTime;
        }

        writer.WriteUInt32(flags);
        if ((flags & SftpConstants.AttrSize) != 0)
        {
            writer.WriteUInt64(Size!.Value);
        }
        if ((flags & SftpConstants.AttrUidGid) != 0)
        {
            writer.WriteUInt32(UserId!.Value);
            writer.WriteUInt32(GroupId!.Value);
        }
        if ((flags & SftpConstants.AttrPermissions) != 0)
        {
            writer.WriteUInt32(Permissions!.Value);
        }
        if ((flags & SftpConstants.AttrAccessModifyTime) != 0)
        {
            writer.WriteUInt32(AccessTime!.Value);
            writer.WriteUInt32(ModifyTime!.Value);
        }
    }
}
