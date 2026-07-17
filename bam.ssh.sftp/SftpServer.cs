using System.Text;

namespace Bam.Ssh.Sftp;

/// <summary>
/// The server side of SFTP v3: serves one <see cref="ISftpChannel"/> (a started <c>sftp</c> subsystem) from
/// an <see cref="ISftpFileSystem"/>. It answers the INIT handshake with VERSION, then processes each request
/// sequentially — parsing the message synchronously into a request, dispatching to the filesystem, and
/// writing the response — keeping a handle table that maps opaque SFTP handles to open file/directory
/// handles. Any <see cref="SftpStatusException"/> a filesystem raises becomes the matching STATUS response;
/// an unknown or unsupported request type is answered <see cref="SftpStatusCode.OperationUnsupported"/>.
/// Processing one request at a time keeps the filesystem free of concurrency concerns and the outbound
/// stream serialized. (SFTP wire types are parsed with the ref-struct <c>SshWireReader</c> in a synchronous
/// step so no ref struct is held across an await.)
/// </summary>
public sealed class SftpServer
{
    /// <summary>The largest single READ this server returns, bounding the response buffer.</summary>
    public const int MaximumReadLength = 256 * 1024;

    private readonly SftpMessageChannel _channel;
    private readonly ISftpFileSystem _fileSystem;
    private readonly ISshLogger _logger;
    private readonly Dictionary<string, ISftpFileHandle> _fileHandles = new Dictionary<string, ISftpFileHandle>(StringComparer.Ordinal);
    private readonly Dictionary<string, ISftpDirectoryHandle> _directoryHandles = new Dictionary<string, ISftpDirectoryHandle>(StringComparer.Ordinal);
    private int _nextHandle;

    /// <summary>
    /// Initializes the server engine.
    /// </summary>
    /// <param name="channel">The SFTP byte channel (a started <c>sftp</c> subsystem).</param>
    /// <param name="fileSystem">The filesystem to serve.</param>
    /// <param name="logger">The logger; defaults to <see cref="NullSshLogger.Instance"/>.</param>
    /// <exception cref="ArgumentNullException">The channel or filesystem is null.</exception>
    public SftpServer(ISftpChannel channel, ISftpFileSystem fileSystem, ISshLogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(channel);
        ArgumentNullException.ThrowIfNull(fileSystem);
        _channel = new SftpMessageChannel(channel);
        _fileSystem = fileSystem;
        _logger = logger ?? NullSshLogger.Instance;
    }

    /// <summary>
    /// Runs the SFTP dialog until the peer closes the channel (a read returns end of stream) or the token is
    /// cancelled, then releases any open handles.
    /// </summary>
    /// <param name="cancellationToken">Cancels serving.</param>
    public async ValueTask RunAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            await HandshakeAsync(cancellationToken).ConfigureAwait(false);
            while (!cancellationToken.IsCancellationRequested)
            {
                SftpRequest request;
                try
                {
                    using SftpMessage message = await _channel.ReadMessageAsync(cancellationToken).ConfigureAwait(false);
                    request = ParseRequest(message);
                }
                catch (SftpException)
                {
                    // The subsystem stream ended; the client closed the channel.
                    break;
                }
                await DispatchAsync(request, cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            await ReleaseHandlesAsync().ConfigureAwait(false);
        }
    }

    private async ValueTask HandshakeAsync(CancellationToken cancellationToken)
    {
        SftpPacketType type;
        using (SftpMessage init = await _channel.ReadMessageAsync(cancellationToken).ConfigureAwait(false))
        {
            type = init.Type;
        }
        if (type != SftpPacketType.Init)
        {
            throw new SftpException($"Expected SFTP INIT but received {type}.");
        }
        using PooledBufferWriter version = BuildVersion();
        await _channel.WriteMessageAsync(SftpPacketType.Version, version.WrittenMemory, cancellationToken).ConfigureAwait(false);
        if (_logger.IsEnabled(SshLogLevel.Information))
        {
            _logger.Log(SshLogLevel.Information, "SFTP server negotiated version {0}.", SftpConstants.Version);
        }
    }

    private static SftpRequest ParseRequest(SftpMessage message)
    {
        SshWireReader reader = message.CreateReader();
        SftpRequest request = new SftpRequest(message.Type, reader.ReadUInt32());
        switch (message.Type)
        {
            case SftpPacketType.Open:
                request.Path = reader.ReadText();
                request.Flags = (SftpOpenFlags)reader.ReadUInt32();
                request.Attributes = SftpFileAttributes.ReadFrom(ref reader);
                break;
            case SftpPacketType.Close:
            case SftpPacketType.ReadDir:
            case SftpPacketType.FStat:
                request.Handle = ReadHandle(ref reader);
                break;
            case SftpPacketType.Read:
                request.Handle = ReadHandle(ref reader);
                request.Offset = reader.ReadUInt64();
                request.Length = reader.ReadUInt32();
                break;
            case SftpPacketType.Write:
                request.Handle = ReadHandle(ref reader);
                request.Offset = reader.ReadUInt64();
                request.Data = reader.ReadString().ToArray();
                break;
            case SftpPacketType.OpenDir:
            case SftpPacketType.Stat:
            case SftpPacketType.LStat:
            case SftpPacketType.RmDir:
            case SftpPacketType.Remove:
            case SftpPacketType.RealPath:
                request.Path = reader.ReadText();
                break;
            case SftpPacketType.MkDir:
            case SftpPacketType.SetStat:
                request.Path = reader.ReadText();
                request.Attributes = SftpFileAttributes.ReadFrom(ref reader);
                break;
            case SftpPacketType.FSetStat:
                request.Handle = ReadHandle(ref reader);
                request.Attributes = SftpFileAttributes.ReadFrom(ref reader);
                break;
            case SftpPacketType.Rename:
                request.Path = reader.ReadText();
                request.SecondPath = reader.ReadText();
                break;
            default:
                break;
        }
        return request;
    }

    private async ValueTask DispatchAsync(SftpRequest request, CancellationToken cancellationToken)
    {
        try
        {
            switch (request.Type)
            {
                case SftpPacketType.Open:
                    await HandleOpenAsync(request, cancellationToken).ConfigureAwait(false);
                    break;
                case SftpPacketType.Close:
                    await HandleCloseAsync(request, cancellationToken).ConfigureAwait(false);
                    break;
                case SftpPacketType.Read:
                    await HandleReadAsync(request, cancellationToken).ConfigureAwait(false);
                    break;
                case SftpPacketType.Write:
                    await HandleWriteAsync(request, cancellationToken).ConfigureAwait(false);
                    break;
                case SftpPacketType.OpenDir:
                    await HandleOpenDirAsync(request, cancellationToken).ConfigureAwait(false);
                    break;
                case SftpPacketType.ReadDir:
                    await HandleReadDirAsync(request, cancellationToken).ConfigureAwait(false);
                    break;
                case SftpPacketType.Stat:
                    await HandleStatAsync(request, followSymbolicLinks: true, cancellationToken).ConfigureAwait(false);
                    break;
                case SftpPacketType.LStat:
                    await HandleStatAsync(request, followSymbolicLinks: false, cancellationToken).ConfigureAwait(false);
                    break;
                case SftpPacketType.FStat:
                    await HandleFStatAsync(request, cancellationToken).ConfigureAwait(false);
                    break;
                case SftpPacketType.SetStat:
                    await _fileSystem.SetAttributesAsync(request.Path, request.Attributes, cancellationToken).ConfigureAwait(false);
                    await WriteStatusAsync(request.Id, SftpStatusCode.Ok, "Attributes set.", cancellationToken).ConfigureAwait(false);
                    break;
                case SftpPacketType.FSetStat:
                    await WriteStatusAsync(request.Id, SftpStatusCode.Ok, "Attributes set.", cancellationToken).ConfigureAwait(false);
                    break;
                case SftpPacketType.MkDir:
                    await _fileSystem.MakeDirectoryAsync(request.Path, request.Attributes, cancellationToken).ConfigureAwait(false);
                    await WriteStatusAsync(request.Id, SftpStatusCode.Ok, "Directory created.", cancellationToken).ConfigureAwait(false);
                    break;
                case SftpPacketType.RmDir:
                    await _fileSystem.RemoveDirectoryAsync(request.Path, cancellationToken).ConfigureAwait(false);
                    await WriteStatusAsync(request.Id, SftpStatusCode.Ok, "Directory removed.", cancellationToken).ConfigureAwait(false);
                    break;
                case SftpPacketType.Remove:
                    await _fileSystem.RemoveFileAsync(request.Path, cancellationToken).ConfigureAwait(false);
                    await WriteStatusAsync(request.Id, SftpStatusCode.Ok, "File removed.", cancellationToken).ConfigureAwait(false);
                    break;
                case SftpPacketType.Rename:
                    await _fileSystem.RenameAsync(request.Path, request.SecondPath, cancellationToken).ConfigureAwait(false);
                    await WriteStatusAsync(request.Id, SftpStatusCode.Ok, "Renamed.", cancellationToken).ConfigureAwait(false);
                    break;
                case SftpPacketType.RealPath:
                    await HandleRealPathAsync(request, cancellationToken).ConfigureAwait(false);
                    break;
                default:
                    await WriteStatusAsync(request.Id, SftpStatusCode.OperationUnsupported, $"Unsupported request {request.Type}.", cancellationToken).ConfigureAwait(false);
                    break;
            }
        }
        catch (SftpStatusException exception)
        {
            await WriteStatusAsync(request.Id, exception.StatusCode, exception.Message, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            await WriteStatusAsync(request.Id, SftpStatusCode.Failure, exception.Message, cancellationToken).ConfigureAwait(false);
        }
    }

    private async ValueTask HandleOpenAsync(SftpRequest request, CancellationToken cancellationToken)
    {
        ISftpFileHandle handle = await _fileSystem.OpenFileAsync(request.Path, request.Flags, request.Attributes, cancellationToken).ConfigureAwait(false);
        string handleId = "f" + Interlocked.Increment(ref _nextHandle).ToString();
        _fileHandles[handleId] = handle;
        await WriteHandleAsync(request.Id, handleId, cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask HandleCloseAsync(SftpRequest request, CancellationToken cancellationToken)
    {
        if (_fileHandles.Remove(request.Handle, out ISftpFileHandle? file))
        {
            await file.DisposeAsync().ConfigureAwait(false);
        }
        else if (_directoryHandles.Remove(request.Handle, out ISftpDirectoryHandle? directory))
        {
            await directory.DisposeAsync().ConfigureAwait(false);
        }
        await WriteStatusAsync(request.Id, SftpStatusCode.Ok, "Closed.", cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask HandleReadAsync(SftpRequest request, CancellationToken cancellationToken)
    {
        ISftpFileHandle handle = GetFileHandle(request.Handle);
        int toRead = (int)Math.Min(request.Length, MaximumReadLength);
        byte[] buffer = new byte[toRead];
        int read = await handle.ReadAsync(request.Offset, buffer, cancellationToken).ConfigureAwait(false);
        if (read == 0)
        {
            await WriteStatusAsync(request.Id, SftpStatusCode.Eof, "End of file.", cancellationToken).ConfigureAwait(false);
            return;
        }
        using PooledBufferWriter data = BuildData(request.Id, buffer, read);
        await _channel.WriteMessageAsync(SftpPacketType.Data, data.WrittenMemory, cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask HandleWriteAsync(SftpRequest request, CancellationToken cancellationToken)
    {
        ISftpFileHandle handle = GetFileHandle(request.Handle);
        await handle.WriteAsync(request.Offset, request.Data, cancellationToken).ConfigureAwait(false);
        await WriteStatusAsync(request.Id, SftpStatusCode.Ok, "Written.", cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask HandleOpenDirAsync(SftpRequest request, CancellationToken cancellationToken)
    {
        ISftpDirectoryHandle handle = await _fileSystem.OpenDirectoryAsync(request.Path, cancellationToken).ConfigureAwait(false);
        string handleId = "d" + Interlocked.Increment(ref _nextHandle).ToString();
        _directoryHandles[handleId] = handle;
        await WriteHandleAsync(request.Id, handleId, cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask HandleReadDirAsync(SftpRequest request, CancellationToken cancellationToken)
    {
        if (!_directoryHandles.TryGetValue(request.Handle, out ISftpDirectoryHandle? handle))
        {
            await WriteStatusAsync(request.Id, SftpStatusCode.Failure, "Unknown directory handle.", cancellationToken).ConfigureAwait(false);
            return;
        }
        IReadOnlyList<SftpName> entries = await handle.ReadAsync(cancellationToken).ConfigureAwait(false);
        if (entries.Count == 0)
        {
            await WriteStatusAsync(request.Id, SftpStatusCode.Eof, "End of directory.", cancellationToken).ConfigureAwait(false);
            return;
        }
        using PooledBufferWriter names = BuildNames(request.Id, entries);
        await _channel.WriteMessageAsync(SftpPacketType.Name, names.WrittenMemory, cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask HandleStatAsync(SftpRequest request, bool followSymbolicLinks, CancellationToken cancellationToken)
    {
        SftpFileAttributes attributes = await _fileSystem.GetAttributesAsync(request.Path, followSymbolicLinks, cancellationToken).ConfigureAwait(false);
        using PooledBufferWriter payload = BuildAttrs(request.Id, attributes);
        await _channel.WriteMessageAsync(SftpPacketType.Attrs, payload.WrittenMemory, cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask HandleFStatAsync(SftpRequest request, CancellationToken cancellationToken)
    {
        ISftpFileHandle handle = GetFileHandle(request.Handle);
        SftpFileAttributes attributes = await handle.GetAttributesAsync(cancellationToken).ConfigureAwait(false);
        using PooledBufferWriter payload = BuildAttrs(request.Id, attributes);
        await _channel.WriteMessageAsync(SftpPacketType.Attrs, payload.WrittenMemory, cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask HandleRealPathAsync(SftpRequest request, CancellationToken cancellationToken)
    {
        string resolved = await _fileSystem.GetRealPathAsync(request.Path, cancellationToken).ConfigureAwait(false);
        SftpName name = new SftpName(resolved, resolved, new SftpFileAttributes(permissions: SftpConstants.ModeDirectory | SftpConstants.DefaultDirectoryPermissions));
        using PooledBufferWriter names = BuildNames(request.Id, new SftpName[] { name });
        await _channel.WriteMessageAsync(SftpPacketType.Name, names.WrittenMemory, cancellationToken).ConfigureAwait(false);
    }

    private ISftpFileHandle GetFileHandle(string handleId)
    {
        if (!_fileHandles.TryGetValue(handleId, out ISftpFileHandle? handle))
        {
            throw new SftpStatusException(SftpStatusCode.Failure, "Unknown file handle.");
        }
        return handle;
    }

    private async ValueTask WriteHandleAsync(uint id, string handleId, CancellationToken cancellationToken)
    {
        using PooledBufferWriter payload = BuildHandle(id, handleId);
        await _channel.WriteMessageAsync(SftpPacketType.Handle, payload.WrittenMemory, cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask WriteStatusAsync(uint id, SftpStatusCode code, string message, CancellationToken cancellationToken)
    {
        using PooledBufferWriter payload = BuildStatus(id, code, message);
        await _channel.WriteMessageAsync(SftpPacketType.Status, payload.WrittenMemory, cancellationToken).ConfigureAwait(false);
    }

    private static PooledBufferWriter BuildVersion()
    {
        PooledBufferWriter writer = new PooledBufferWriter(4);
        SshWireWriter wire = new SshWireWriter(writer);
        wire.WriteUInt32(SftpConstants.Version);
        return writer;
    }

    private static PooledBufferWriter BuildStatus(uint id, SftpStatusCode code, string message)
    {
        PooledBufferWriter writer = new PooledBufferWriter(32 + message.Length);
        SshWireWriter wire = new SshWireWriter(writer);
        wire.WriteUInt32(id);
        wire.WriteUInt32((uint)code);
        wire.WriteText(message);
        wire.WriteText(string.Empty);
        return writer;
    }

    private static PooledBufferWriter BuildHandle(uint id, string handleId)
    {
        PooledBufferWriter writer = new PooledBufferWriter(16);
        SshWireWriter wire = new SshWireWriter(writer);
        wire.WriteUInt32(id);
        wire.WriteString(Encoding.ASCII.GetBytes(handleId));
        return writer;
    }

    private static PooledBufferWriter BuildData(uint id, byte[] buffer, int length)
    {
        PooledBufferWriter writer = new PooledBufferWriter(8 + length);
        SshWireWriter wire = new SshWireWriter(writer);
        wire.WriteUInt32(id);
        wire.WriteString(buffer.AsSpan(0, length));
        return writer;
    }

    private static PooledBufferWriter BuildAttrs(uint id, SftpFileAttributes attributes)
    {
        PooledBufferWriter writer = new PooledBufferWriter(32);
        SshWireWriter wire = new SshWireWriter(writer);
        wire.WriteUInt32(id);
        attributes.WriteTo(ref wire);
        return writer;
    }

    private static PooledBufferWriter BuildNames(uint id, IReadOnlyList<SftpName> entries)
    {
        PooledBufferWriter writer = new PooledBufferWriter(256);
        SshWireWriter wire = new SshWireWriter(writer);
        wire.WriteUInt32(id);
        wire.WriteUInt32((uint)entries.Count);
        foreach (SftpName entry in entries)
        {
            wire.WriteText(entry.FileName);
            wire.WriteText(entry.LongName);
            entry.Attributes.WriteTo(ref wire);
        }
        return writer;
    }

    private static string ReadHandle(ref SshWireReader reader)
    {
        ReadOnlySpan<byte> handle = reader.ReadString();
        return Encoding.ASCII.GetString(handle);
    }

    private async ValueTask ReleaseHandlesAsync()
    {
        foreach (ISftpFileHandle handle in _fileHandles.Values)
        {
            await handle.DisposeAsync().ConfigureAwait(false);
        }
        _fileHandles.Clear();
        foreach (ISftpDirectoryHandle handle in _directoryHandles.Values)
        {
            await handle.DisposeAsync().ConfigureAwait(false);
        }
        _directoryHandles.Clear();
    }

    private sealed class SftpRequest
    {
        public SftpRequest(SftpPacketType type, uint id)
        {
            Type = type;
            Id = id;
        }

        public SftpPacketType Type { get; }

        public uint Id { get; }

        public string Path { get; set; } = string.Empty;

        public string SecondPath { get; set; } = string.Empty;

        public string Handle { get; set; } = string.Empty;

        public ulong Offset { get; set; }

        public uint Length { get; set; }

        public byte[] Data { get; set; } = Array.Empty<byte>();

        public SftpOpenFlags Flags { get; set; }

        public SftpFileAttributes Attributes { get; set; } = new SftpFileAttributes();
    }
}
