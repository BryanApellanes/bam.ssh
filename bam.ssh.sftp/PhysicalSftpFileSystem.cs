using Microsoft.Win32.SafeHandles;

namespace Bam.Ssh.Sftp;

/// <summary>
/// An <see cref="ISftpFileSystem"/> that maps the SFTP path namespace onto a real OS directory subtree. The
/// server's canonical '/'-paths are resolved against a fixed root directory and <b>jailed</b> to it — any
/// path that would escape the root (via <c>..</c> or an absolute host path) is refused with
/// <see cref="SftpStatusCode.PermissionDenied"/>, so a peer can only ever reach files under the root.
/// Positional reads and writes use <see cref="RandomAccess"/> so a handle needs no file-pointer state.
/// </summary>
public sealed class PhysicalSftpFileSystem : ISftpFileSystem
{
    private readonly string _rootFullPath;

    /// <summary>
    /// Initializes the filesystem rooted at a directory. The directory must already exist.
    /// </summary>
    /// <param name="rootDirectory">The host directory that becomes the SFTP root.</param>
    /// <exception cref="ArgumentException">The root is null or empty.</exception>
    /// <exception cref="SftpException">The root directory does not exist.</exception>
    public PhysicalSftpFileSystem(string rootDirectory)
    {
        ArgumentException.ThrowIfNullOrEmpty(rootDirectory);
        if (!Directory.Exists(rootDirectory))
        {
            throw new SftpException($"The SFTP root directory '{rootDirectory}' does not exist.");
        }
        _rootFullPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(rootDirectory));
    }

    /// <inheritdoc/>
    public ValueTask<SftpFileAttributes> GetAttributesAsync(string path, bool followSymbolicLinks, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(path);
        string hostPath = MapToHost(path);
        if (Directory.Exists(hostPath))
        {
            return ValueTask.FromResult(DirectoryAttributes(hostPath));
        }
        if (File.Exists(hostPath))
        {
            return ValueTask.FromResult(FileAttributes(hostPath));
        }
        throw new SftpStatusException(SftpStatusCode.NoSuchFile, $"'{path}' does not exist.");
    }

    /// <inheritdoc/>
    public ValueTask SetAttributesAsync(string path, SftpFileAttributes attributes, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(attributes);
        string hostPath = MapToHost(path);
        if (attributes.ModifyTime is uint mtime && File.Exists(hostPath))
        {
            File.SetLastWriteTimeUtc(hostPath, DateTimeOffset.FromUnixTimeSeconds(mtime).UtcDateTime);
        }
        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public ValueTask<ISftpFileHandle> OpenFileAsync(string path, SftpOpenFlags flags, SftpFileAttributes attributes, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(path);
        string hostPath = MapToHost(path);
        if (Directory.Exists(hostPath))
        {
            throw new SftpStatusException(SftpStatusCode.Failure, $"'{path}' is a directory.");
        }

        FileMode mode = ToFileMode(flags);
        FileAccess access = ToFileAccess(flags);
        try
        {
            SafeFileHandle handle = File.OpenHandle(hostPath, mode, access, FileShare.ReadWrite);
            bool append = (flags & SftpOpenFlags.Append) != 0;
            return ValueTask.FromResult<ISftpFileHandle>(new PhysicalFileHandle(handle, append));
        }
        catch (FileNotFoundException exception)
        {
            throw new SftpStatusException(SftpStatusCode.NoSuchFile, exception.Message);
        }
        catch (DirectoryNotFoundException exception)
        {
            throw new SftpStatusException(SftpStatusCode.NoSuchFile, exception.Message);
        }
        catch (IOException exception)
        {
            throw new SftpStatusException(SftpStatusCode.Failure, exception.Message);
        }
        catch (UnauthorizedAccessException exception)
        {
            throw new SftpStatusException(SftpStatusCode.PermissionDenied, exception.Message);
        }
    }

    /// <inheritdoc/>
    public ValueTask<ISftpDirectoryHandle> OpenDirectoryAsync(string path, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(path);
        string hostPath = MapToHost(path);
        if (!Directory.Exists(hostPath))
        {
            throw new SftpStatusException(SftpStatusCode.NoSuchFile, $"'{path}' is not a directory.");
        }

        List<SftpName> entries = new List<SftpName>();
        entries.Add(DirectoryEntry(".", hostPath));
        entries.Add(DirectoryEntry("..", hostPath));
        foreach (string entry in Directory.EnumerateFileSystemEntries(hostPath))
        {
            string name = Path.GetFileName(entry);
            SftpFileAttributes attributes = Directory.Exists(entry) ? DirectoryAttributes(entry) : FileAttributes(entry);
            entries.Add(new SftpName(name, SftpLongName.Format(name, attributes), attributes));
        }
        return ValueTask.FromResult<ISftpDirectoryHandle>(new ListDirectoryHandle(entries));
    }

    /// <inheritdoc/>
    public ValueTask MakeDirectoryAsync(string path, SftpFileAttributes attributes, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(path);
        string hostPath = MapToHost(path);
        if (Directory.Exists(hostPath) || File.Exists(hostPath))
        {
            throw new SftpStatusException(SftpStatusCode.Failure, $"'{path}' already exists.");
        }
        Directory.CreateDirectory(hostPath);
        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public ValueTask RemoveDirectoryAsync(string path, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(path);
        string hostPath = MapToHost(path);
        if (!Directory.Exists(hostPath))
        {
            throw new SftpStatusException(SftpStatusCode.NoSuchFile, $"'{path}' is not a directory.");
        }
        if (Directory.EnumerateFileSystemEntries(hostPath).Any())
        {
            throw new SftpStatusException(SftpStatusCode.Failure, $"'{path}' is not empty.");
        }
        Directory.Delete(hostPath);
        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public ValueTask RemoveFileAsync(string path, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(path);
        string hostPath = MapToHost(path);
        if (!File.Exists(hostPath))
        {
            throw new SftpStatusException(SftpStatusCode.NoSuchFile, $"'{path}' is not a file.");
        }
        File.Delete(hostPath);
        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public ValueTask RenameAsync(string oldPath, string newPath, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(oldPath);
        ArgumentNullException.ThrowIfNull(newPath);
        string oldHost = MapToHost(oldPath);
        string newHost = MapToHost(newPath);
        if (Directory.Exists(newHost) || File.Exists(newHost))
        {
            throw new SftpStatusException(SftpStatusCode.Failure, $"'{newPath}' already exists.");
        }
        if (Directory.Exists(oldHost))
        {
            Directory.Move(oldHost, newHost);
        }
        else if (File.Exists(oldHost))
        {
            File.Move(oldHost, newHost);
        }
        else
        {
            throw new SftpStatusException(SftpStatusCode.NoSuchFile, $"'{oldPath}' does not exist.");
        }
        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public ValueTask<string> GetRealPathAsync(string path, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(path);
        return ValueTask.FromResult(SftpPath.Canonicalize(path));
    }

    private string MapToHost(string sftpPath)
    {
        string canonical = SftpPath.Canonicalize(sftpPath);
        string[] segments = SftpPath.Split(canonical);
        string combined = segments.Length == 0 ? _rootFullPath : Path.Combine(_rootFullPath, Path.Combine(segments));
        string fullPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(combined));
        if (!IsWithinRoot(fullPath))
        {
            throw new SftpStatusException(SftpStatusCode.PermissionDenied, $"'{sftpPath}' is outside the served root.");
        }
        return fullPath;
    }

    private bool IsWithinRoot(string fullPath)
    {
        if (string.Equals(fullPath, _rootFullPath, PathComparison))
        {
            return true;
        }
        string prefix = _rootFullPath + Path.DirectorySeparatorChar;
        return fullPath.StartsWith(prefix, PathComparison);
    }

    private static StringComparison PathComparison =>
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

    private static SftpFileAttributes DirectoryAttributes(string hostPath)
    {
        uint mtime = ToUnixTime(Directory.GetLastWriteTimeUtc(hostPath));
        return new SftpFileAttributes(
            size: 0,
            permissions: SftpConstants.ModeDirectory | SftpConstants.DefaultDirectoryPermissions,
            accessTime: mtime,
            modifyTime: mtime);
    }

    private static SftpFileAttributes FileAttributes(string hostPath)
    {
        FileInfo info = new FileInfo(hostPath);
        uint mtime = ToUnixTime(info.LastWriteTimeUtc);
        return new SftpFileAttributes(
            size: (ulong)info.Length,
            permissions: SftpConstants.ModeRegularFile | SftpConstants.DefaultFilePermissions,
            accessTime: mtime,
            modifyTime: mtime);
    }

    private static SftpName DirectoryEntry(string name, string hostPath)
    {
        SftpFileAttributes attributes = DirectoryAttributes(hostPath);
        return new SftpName(name, SftpLongName.Format(name, attributes), attributes);
    }

    private static uint ToUnixTime(DateTime utc)
    {
        long seconds = new DateTimeOffset(utc, TimeSpan.Zero).ToUnixTimeSeconds();
        return seconds < 0 ? 0 : (uint)seconds;
    }

    private static FileMode ToFileMode(SftpOpenFlags flags)
    {
        bool create = (flags & SftpOpenFlags.Create) != 0;
        bool truncate = (flags & SftpOpenFlags.Truncate) != 0;
        bool exclusive = (flags & SftpOpenFlags.Exclusive) != 0;
        if (create && exclusive)
        {
            return FileMode.CreateNew;
        }
        if (create && truncate)
        {
            return FileMode.Create;
        }
        if (create)
        {
            return FileMode.OpenOrCreate;
        }
        if (truncate)
        {
            return FileMode.Truncate;
        }
        return FileMode.Open;
    }

    private static FileAccess ToFileAccess(SftpOpenFlags flags)
    {
        bool read = (flags & SftpOpenFlags.Read) != 0;
        bool write = (flags & (SftpOpenFlags.Write | SftpOpenFlags.Append | SftpOpenFlags.Create | SftpOpenFlags.Truncate)) != 0;
        if (read && write)
        {
            return FileAccess.ReadWrite;
        }
        return write ? FileAccess.Write : FileAccess.Read;
    }

    private sealed class PhysicalFileHandle : ISftpFileHandle
    {
        private readonly SafeFileHandle _handle;
        private readonly bool _append;

        public PhysicalFileHandle(SafeFileHandle handle, bool append)
        {
            _handle = handle;
            _append = append;
        }

        public async ValueTask<int> ReadAsync(ulong offset, Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            return await RandomAccess.ReadAsync(_handle, buffer, (long)offset, cancellationToken).ConfigureAwait(false);
        }

        public async ValueTask WriteAsync(ulong offset, ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
        {
            long at = _append ? RandomAccess.GetLength(_handle) : (long)offset;
            await RandomAccess.WriteAsync(_handle, data, at, cancellationToken).ConfigureAwait(false);
        }

        public ValueTask<SftpFileAttributes> GetAttributesAsync(CancellationToken cancellationToken = default)
        {
            long length = RandomAccess.GetLength(_handle);
            return ValueTask.FromResult(new SftpFileAttributes(
                size: (ulong)length,
                permissions: SftpConstants.ModeRegularFile | SftpConstants.DefaultFilePermissions));
        }

        public ValueTask DisposeAsync()
        {
            _handle.Dispose();
            return ValueTask.CompletedTask;
        }
    }

    private sealed class ListDirectoryHandle : ISftpDirectoryHandle
    {
        private readonly IReadOnlyList<SftpName> _entries;
        private bool _served;

        public ListDirectoryHandle(IReadOnlyList<SftpName> entries)
        {
            _entries = entries;
        }

        public ValueTask<IReadOnlyList<SftpName>> ReadAsync(CancellationToken cancellationToken = default)
        {
            if (_served)
            {
                return ValueTask.FromResult<IReadOnlyList<SftpName>>(Array.Empty<SftpName>());
            }
            _served = true;
            return ValueTask.FromResult(_entries);
        }

        public ValueTask DisposeAsync()
        {
            return ValueTask.CompletedTask;
        }
    }
}
