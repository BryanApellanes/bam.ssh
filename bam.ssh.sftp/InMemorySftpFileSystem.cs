namespace Bam.Ssh.Sftp;

/// <summary>
/// An in-memory <see cref="ISftpFileSystem"/> backed by a dictionary tree of directories and byte-array
/// files. Ideal for tests and ephemeral servers: no disk, deterministic, and fully sandboxed (a path can
/// never escape the tree). Mutations are guarded by a lock so the server may serve requests without external
/// synchronization.
/// </summary>
public sealed class InMemorySftpFileSystem : ISftpFileSystem
{
    private readonly object _sync = new object();
    private readonly DirectoryNode _root = new DirectoryNode();

    /// <inheritdoc/>
    public ValueTask<SftpFileAttributes> GetAttributesAsync(string path, bool followSymbolicLinks, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(path);
        lock (_sync)
        {
            Node node = ResolveExisting(path);
            return ValueTask.FromResult(node.GetAttributes());
        }
    }

    /// <inheritdoc/>
    public ValueTask SetAttributesAsync(string path, SftpFileAttributes attributes, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(attributes);
        lock (_sync)
        {
            Node node = ResolveExisting(path);
            if (attributes.Permissions.HasValue)
            {
                node.Permissions = (attributes.Permissions.Value & ~SftpConstants.ModeFormatMask) | (node.Permissions & SftpConstants.ModeFormatMask);
            }
            if (attributes.Size is ulong size && node is FileNode file)
            {
                file.Truncate((int)size);
            }
        }
        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public ValueTask<ISftpFileHandle> OpenFileAsync(string path, SftpOpenFlags flags, SftpFileAttributes attributes, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(path);
        lock (_sync)
        {
            string canonical = SftpPath.Canonicalize(path);
            string name = SftpPath.GetFileName(canonical);
            if (name.Length == 0)
            {
                throw new SftpStatusException(SftpStatusCode.Failure, "Cannot open the root as a file.");
            }
            DirectoryNode parent = ResolveDirectory(SftpPath.GetParent(canonical));

            parent.Children.TryGetValue(name, out Node? existing);
            if (existing is DirectoryNode)
            {
                throw new SftpStatusException(SftpStatusCode.Failure, $"'{canonical}' is a directory.");
            }
            FileNode? node = existing as FileNode;

            if (node == null)
            {
                if ((flags & SftpOpenFlags.Create) == 0)
                {
                    throw new SftpStatusException(SftpStatusCode.NoSuchFile, $"'{canonical}' does not exist.");
                }
                node = new FileNode
                {
                    Permissions = SftpConstants.ModeRegularFile | (attributes.Permissions ?? SftpConstants.DefaultFilePermissions) & ~SftpConstants.ModeFormatMask,
                };
                parent.Children[name] = node;
            }
            else if ((flags & (SftpOpenFlags.Create | SftpOpenFlags.Exclusive)) == (SftpOpenFlags.Create | SftpOpenFlags.Exclusive))
            {
                throw new SftpStatusException(SftpStatusCode.Failure, $"'{canonical}' already exists.");
            }

            if ((flags & SftpOpenFlags.Truncate) != 0)
            {
                node.Truncate(0);
            }

            ISftpFileHandle handle = new InMemoryFileHandle(node, _sync, (flags & SftpOpenFlags.Append) != 0);
            return ValueTask.FromResult(handle);
        }
    }

    /// <inheritdoc/>
    public ValueTask<ISftpDirectoryHandle> OpenDirectoryAsync(string path, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(path);
        lock (_sync)
        {
            DirectoryNode directory = ResolveDirectory(path);
            List<SftpName> entries = new List<SftpName>(directory.Children.Count + 2);
            entries.Add(new SftpName(".", SftpLongName.Format(".", directory.GetAttributes()), directory.GetAttributes()));
            entries.Add(new SftpName("..", SftpLongName.Format("..", directory.GetAttributes()), directory.GetAttributes()));
            foreach (KeyValuePair<string, Node> child in directory.Children)
            {
                SftpFileAttributes attributes = child.Value.GetAttributes();
                entries.Add(new SftpName(child.Key, SftpLongName.Format(child.Key, attributes), attributes));
            }
            ISftpDirectoryHandle handle = new InMemoryDirectoryHandle(entries);
            return ValueTask.FromResult(handle);
        }
    }

    /// <inheritdoc/>
    public ValueTask MakeDirectoryAsync(string path, SftpFileAttributes attributes, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(path);
        lock (_sync)
        {
            string canonical = SftpPath.Canonicalize(path);
            string name = SftpPath.GetFileName(canonical);
            if (name.Length == 0)
            {
                throw new SftpStatusException(SftpStatusCode.Failure, "Cannot create the root directory.");
            }
            DirectoryNode parent = ResolveDirectory(SftpPath.GetParent(canonical));
            if (parent.Children.ContainsKey(name))
            {
                throw new SftpStatusException(SftpStatusCode.Failure, $"'{canonical}' already exists.");
            }
            parent.Children[name] = new DirectoryNode
            {
                Permissions = SftpConstants.ModeDirectory | (attributes.Permissions ?? SftpConstants.DefaultDirectoryPermissions) & ~SftpConstants.ModeFormatMask,
            };
        }
        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public ValueTask RemoveDirectoryAsync(string path, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(path);
        lock (_sync)
        {
            string canonical = SftpPath.Canonicalize(path);
            string name = SftpPath.GetFileName(canonical);
            DirectoryNode parent = ResolveDirectory(SftpPath.GetParent(canonical));
            if (!parent.Children.TryGetValue(name, out Node? node) || node is not DirectoryNode directory)
            {
                throw new SftpStatusException(SftpStatusCode.NoSuchFile, $"'{canonical}' is not a directory.");
            }
            if (directory.Children.Count > 0)
            {
                throw new SftpStatusException(SftpStatusCode.Failure, $"'{canonical}' is not empty.");
            }
            parent.Children.Remove(name);
        }
        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public ValueTask RemoveFileAsync(string path, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(path);
        lock (_sync)
        {
            string canonical = SftpPath.Canonicalize(path);
            string name = SftpPath.GetFileName(canonical);
            DirectoryNode parent = ResolveDirectory(SftpPath.GetParent(canonical));
            if (!parent.Children.TryGetValue(name, out Node? node) || node is not FileNode)
            {
                throw new SftpStatusException(SftpStatusCode.NoSuchFile, $"'{canonical}' is not a file.");
            }
            parent.Children.Remove(name);
        }
        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public ValueTask RenameAsync(string oldPath, string newPath, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(oldPath);
        ArgumentNullException.ThrowIfNull(newPath);
        lock (_sync)
        {
            string oldCanonical = SftpPath.Canonicalize(oldPath);
            string oldName = SftpPath.GetFileName(oldCanonical);
            DirectoryNode oldParent = ResolveDirectory(SftpPath.GetParent(oldCanonical));
            if (!oldParent.Children.TryGetValue(oldName, out Node? node))
            {
                throw new SftpStatusException(SftpStatusCode.NoSuchFile, $"'{oldCanonical}' does not exist.");
            }

            string newCanonical = SftpPath.Canonicalize(newPath);
            string newName = SftpPath.GetFileName(newCanonical);
            DirectoryNode newParent = ResolveDirectory(SftpPath.GetParent(newCanonical));
            if (newParent.Children.ContainsKey(newName))
            {
                throw new SftpStatusException(SftpStatusCode.Failure, $"'{newCanonical}' already exists.");
            }
            oldParent.Children.Remove(oldName);
            newParent.Children[newName] = node;
        }
        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public ValueTask<string> GetRealPathAsync(string path, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(path);
        return ValueTask.FromResult(SftpPath.Canonicalize(path));
    }

    private Node ResolveExisting(string path)
    {
        string canonical = SftpPath.Canonicalize(path);
        Node current = _root;
        foreach (string segment in SftpPath.Split(canonical))
        {
            if (current is not DirectoryNode directory || !directory.Children.TryGetValue(segment, out Node? next))
            {
                throw new SftpStatusException(SftpStatusCode.NoSuchFile, $"'{canonical}' does not exist.");
            }
            current = next;
        }
        return current;
    }

    private DirectoryNode ResolveDirectory(string path)
    {
        Node node = ResolveExisting(path);
        if (node is not DirectoryNode directory)
        {
            throw new SftpStatusException(SftpStatusCode.NoSuchFile, $"'{SftpPath.Canonicalize(path)}' is not a directory.");
        }
        return directory;
    }

    private abstract class Node
    {
        public uint Permissions { get; set; }

        public abstract SftpFileAttributes GetAttributes();
    }

    private sealed class DirectoryNode : Node
    {
        public DirectoryNode()
        {
            Permissions = SftpConstants.ModeDirectory | SftpConstants.DefaultDirectoryPermissions;
        }

        public Dictionary<string, Node> Children { get; } = new Dictionary<string, Node>(StringComparer.Ordinal);

        public override SftpFileAttributes GetAttributes()
        {
            return new SftpFileAttributes(size: 0, permissions: Permissions);
        }
    }

    private sealed class FileNode : Node
    {
        private byte[] _data = Array.Empty<byte>();

        public FileNode()
        {
            Permissions = SftpConstants.ModeRegularFile | SftpConstants.DefaultFilePermissions;
        }

        public int Length => _data.Length;

        public override SftpFileAttributes GetAttributes()
        {
            return new SftpFileAttributes(size: (ulong)_data.Length, permissions: Permissions);
        }

        public int Read(int offset, Span<byte> buffer)
        {
            if (offset >= _data.Length)
            {
                return 0;
            }
            int available = Math.Min(buffer.Length, _data.Length - offset);
            _data.AsSpan(offset, available).CopyTo(buffer);
            return available;
        }

        public void Write(int offset, ReadOnlySpan<byte> data)
        {
            int end = offset + data.Length;
            if (end > _data.Length)
            {
                Array.Resize(ref _data, end);
            }
            data.CopyTo(_data.AsSpan(offset));
        }

        public void Truncate(int length)
        {
            Array.Resize(ref _data, length);
        }
    }

    private sealed class InMemoryFileHandle : ISftpFileHandle
    {
        private readonly FileNode _node;
        private readonly object _sync;
        private readonly bool _append;

        public InMemoryFileHandle(FileNode node, object sync, bool append)
        {
            _node = node;
            _sync = sync;
            _append = append;
        }

        public ValueTask<int> ReadAsync(ulong offset, Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            lock (_sync)
            {
                return ValueTask.FromResult(_node.Read((int)offset, buffer.Span));
            }
        }

        public ValueTask WriteAsync(ulong offset, ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
        {
            lock (_sync)
            {
                int at = _append ? _node.Length : (int)offset;
                _node.Write(at, data.Span);
            }
            return ValueTask.CompletedTask;
        }

        public ValueTask<SftpFileAttributes> GetAttributesAsync(CancellationToken cancellationToken = default)
        {
            lock (_sync)
            {
                return ValueTask.FromResult(_node.GetAttributes());
            }
        }

        public ValueTask DisposeAsync()
        {
            return ValueTask.CompletedTask;
        }
    }

    private sealed class InMemoryDirectoryHandle : ISftpDirectoryHandle
    {
        private readonly IReadOnlyList<SftpName> _entries;
        private bool _served;

        public InMemoryDirectoryHandle(IReadOnlyList<SftpName> entries)
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
