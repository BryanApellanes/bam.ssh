using System.Collections.Concurrent;
using System.Text;
using Bam.Ssh.Connection;

namespace Bam.Ssh.Sftp;

/// <summary>
/// The client side of SFTP v3 over a started <c>sftp</c> subsystem channel. It performs the INIT/VERSION
/// handshake, then runs a single background reader loop that correlates each server response to the pending
/// request by its <c>uint32</c> id (mirroring <c>SshConnection</c>'s single-reader discipline), so many
/// operations can be outstanding without racing on the channel. Exposes the SFTP primitives plus high-level
/// <see cref="UploadAsync"/>/<see cref="DownloadAsync"/>/<see cref="ListDirectoryAsync"/>. Disposing stops
/// the reader loop.
/// </summary>
public sealed class SftpClient : IAsyncDisposable
{
    private const int TransferChunkSize = 32 * 1024;

    private readonly SftpMessageChannel _channel;
    private readonly ISshLogger _logger;
    private readonly SemaphoreSlim _writeLock = new SemaphoreSlim(1, 1);
    private readonly ConcurrentDictionary<uint, TaskCompletionSource<SftpResponse>> _pending = new ConcurrentDictionary<uint, TaskCompletionSource<SftpResponse>>();
    private readonly CancellationTokenSource _shutdown = new CancellationTokenSource();

    private Task _readerLoop = Task.CompletedTask;
    private int _nextRequestId;
    private uint _serverVersion;
    private bool _disposed;

    /// <summary>
    /// Initializes the client over an SFTP byte channel. Call <see cref="ConnectAsync"/> before any
    /// operation, or use <see cref="OpenAsync(SshSessionChannel, CancellationToken)"/> to do both.
    /// </summary>
    /// <param name="channel">The SFTP byte channel (a started <c>sftp</c> subsystem).</param>
    /// <param name="logger">The logger; defaults to <see cref="NullSshLogger.Instance"/>.</param>
    /// <exception cref="ArgumentNullException">The channel is null.</exception>
    public SftpClient(ISftpChannel channel, ISshLogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(channel);
        _channel = new SftpMessageChannel(channel);
        _logger = logger ?? NullSshLogger.Instance;
    }

    /// <summary>Gets the SFTP version the server agreed to (valid after <see cref="ConnectAsync"/>).</summary>
    public uint ServerVersion => _serverVersion;

    /// <summary>
    /// Starts the <c>sftp</c> subsystem on a session channel and returns a connected client over it.
    /// </summary>
    /// <param name="channel">A session channel opened on an authenticated connection.</param>
    /// <param name="cancellationToken">Cancels the start and handshake.</param>
    /// <returns>The connected client.</returns>
    /// <exception cref="ArgumentNullException">The channel is null.</exception>
    /// <exception cref="SftpException">The server refused the subsystem or the handshake failed.</exception>
    public static async ValueTask<SftpClient> OpenAsync(SshSessionChannel channel, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(channel);
        if (!await channel.SubsystemAsync("sftp", cancellationToken).ConfigureAwait(false))
        {
            throw new SftpException("The server refused to start the sftp subsystem.");
        }
        SftpClient client = new SftpClient(new SshChannelSftpChannel(channel.Channel));
        await client.ConnectAsync(cancellationToken).ConfigureAwait(false);
        return client;
    }

    /// <summary>
    /// Performs the INIT/VERSION handshake and starts the background reader loop.
    /// </summary>
    /// <param name="cancellationToken">Cancels the handshake.</param>
    /// <exception cref="SftpException">The server did not answer with a compatible VERSION.</exception>
    public async ValueTask ConnectAsync(CancellationToken cancellationToken = default)
    {
        using (PooledBufferWriter init = new PooledBufferWriter(4))
        {
            SshWireWriter wire = new SshWireWriter(init);
            wire.WriteUInt32(SftpConstants.Version);
            await SendAsync(SftpPacketType.Init, init.WrittenMemory, cancellationToken).ConfigureAwait(false);
        }

        uint version;
        using (SftpMessage message = await _channel.ReadMessageAsync(cancellationToken).ConfigureAwait(false))
        {
            if (message.Type != SftpPacketType.Version)
            {
                throw new SftpException($"Expected SFTP VERSION but received {message.Type}.");
            }
            SshWireReader reader = message.CreateReader();
            version = reader.ReadUInt32();
        }
        _serverVersion = version;
        _readerLoop = ReadLoopAsync(_shutdown.Token);
    }

    /// <summary>Opens (or creates) a remote file, returning its handle.</summary>
    /// <param name="path">The remote path.</param>
    /// <param name="flags">The open flags.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The opaque file handle.</returns>
    public async ValueTask<string> OpenFileAsync(string path, SftpOpenFlags flags, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(path);
        uint id = NextId();
        using PooledBufferWriter payload = BuildOpen(id, path, flags);
        SftpResponse response = await ExchangeAsync(id, SftpPacketType.Open, payload, cancellationToken).ConfigureAwait(false);
        return ExpectHandle(response);
    }

    /// <summary>Closes an open file or directory handle.</summary>
    /// <param name="handle">The handle.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    public async ValueTask CloseHandleAsync(string handle, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(handle);
        uint id = NextId();
        using PooledBufferWriter payload = BuildHandleRequest(id, handle);
        SftpResponse response = await ExchangeAsync(id, SftpPacketType.Close, payload, cancellationToken).ConfigureAwait(false);
        ExpectOk(response);
    }

    /// <summary>Reads up to <paramref name="length"/> bytes from an open file at an offset.</summary>
    /// <param name="handle">The file handle.</param>
    /// <param name="offset">The byte offset.</param>
    /// <param name="length">The maximum number of bytes to read.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The bytes read; empty at end of file.</returns>
    public async ValueTask<byte[]> ReadFileAsync(string handle, ulong offset, uint length, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(handle);
        uint id = NextId();
        using PooledBufferWriter payload = BuildRead(id, handle, offset, length);
        SftpResponse response = await ExchangeAsync(id, SftpPacketType.Read, payload, cancellationToken).ConfigureAwait(false);
        if (response.Type == SftpPacketType.Status && response.StatusCode == SftpStatusCode.Eof)
        {
            return Array.Empty<byte>();
        }
        if (response.Type != SftpPacketType.Data)
        {
            throw ToException(response, "READ");
        }
        return response.Data;
    }

    /// <summary>Writes bytes to an open file at an offset.</summary>
    /// <param name="handle">The file handle.</param>
    /// <param name="offset">The byte offset.</param>
    /// <param name="data">The bytes to write.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    public async ValueTask WriteFileAsync(string handle, ulong offset, ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(handle);
        uint id = NextId();
        using PooledBufferWriter payload = BuildWrite(id, handle, offset, data.Span);
        SftpResponse response = await ExchangeAsync(id, SftpPacketType.Write, payload, cancellationToken).ConfigureAwait(false);
        ExpectOk(response);
    }

    /// <summary>Gets the attributes of a remote path (following symbolic links).</summary>
    /// <param name="path">The remote path.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The path's attributes.</returns>
    public async ValueTask<SftpFileAttributes> GetAttributesAsync(string path, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(path);
        uint id = NextId();
        using PooledBufferWriter payload = BuildPath(id, path);
        SftpResponse response = await ExchangeAsync(id, SftpPacketType.Stat, payload, cancellationToken).ConfigureAwait(false);
        if (response.Type != SftpPacketType.Attrs || response.Attributes == null)
        {
            throw ToException(response, "STAT");
        }
        return response.Attributes;
    }

    /// <summary>Creates a remote directory.</summary>
    /// <param name="path">The remote path.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    public ValueTask MakeDirectoryAsync(string path, CancellationToken cancellationToken = default)
    {
        return PathStatusAsync(SftpPacketType.MkDir, path, withAttributes: true, cancellationToken);
    }

    /// <summary>Removes an empty remote directory.</summary>
    /// <param name="path">The remote path.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    public ValueTask RemoveDirectoryAsync(string path, CancellationToken cancellationToken = default)
    {
        return PathStatusAsync(SftpPacketType.RmDir, path, withAttributes: false, cancellationToken);
    }

    /// <summary>Removes a remote file.</summary>
    /// <param name="path">The remote path.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    public ValueTask RemoveFileAsync(string path, CancellationToken cancellationToken = default)
    {
        return PathStatusAsync(SftpPacketType.Remove, path, withAttributes: false, cancellationToken);
    }

    /// <summary>Renames (or moves) a remote file or directory.</summary>
    /// <param name="oldPath">The existing path.</param>
    /// <param name="newPath">The new path.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    public async ValueTask RenameAsync(string oldPath, string newPath, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(oldPath);
        ArgumentNullException.ThrowIfNull(newPath);
        uint id = NextId();
        using PooledBufferWriter payload = BuildRename(id, oldPath, newPath);
        SftpResponse response = await ExchangeAsync(id, SftpPacketType.Rename, payload, cancellationToken).ConfigureAwait(false);
        ExpectOk(response);
    }

    /// <summary>Canonicalizes a remote path to its absolute form.</summary>
    /// <param name="path">The path to canonicalize.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The canonical path.</returns>
    public async ValueTask<string> GetRealPathAsync(string path, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(path);
        uint id = NextId();
        using PooledBufferWriter payload = BuildPath(id, path);
        SftpResponse response = await ExchangeAsync(id, SftpPacketType.RealPath, payload, cancellationToken).ConfigureAwait(false);
        if (response.Type != SftpPacketType.Name || response.Names.Count == 0)
        {
            throw ToException(response, "REALPATH");
        }
        return response.Names[0].FileName;
    }

    /// <summary>Lists a remote directory's entries (excluding <c>.</c> and <c>..</c>).</summary>
    /// <param name="path">The remote directory path.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The directory entries.</returns>
    public async ValueTask<IReadOnlyList<SftpName>> ListDirectoryAsync(string path, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(path);
        uint openId = NextId();
        using PooledBufferWriter openPayload = BuildPath(openId, path);
        SftpResponse openResponse = await ExchangeAsync(openId, SftpPacketType.OpenDir, openPayload, cancellationToken).ConfigureAwait(false);
        string handle = ExpectHandle(openResponse);

        List<SftpName> entries = new List<SftpName>();
        try
        {
            while (true)
            {
                uint id = NextId();
                using PooledBufferWriter payload = BuildHandleRequest(id, handle);
                SftpResponse response = await ExchangeAsync(id, SftpPacketType.ReadDir, payload, cancellationToken).ConfigureAwait(false);
                if (response.Type == SftpPacketType.Status && response.StatusCode == SftpStatusCode.Eof)
                {
                    break;
                }
                if (response.Type != SftpPacketType.Name)
                {
                    throw ToException(response, "READDIR");
                }
                foreach (SftpName entry in response.Names)
                {
                    if (entry.FileName != "." && entry.FileName != "..")
                    {
                        entries.Add(entry);
                    }
                }
            }
        }
        finally
        {
            await CloseHandleAsync(handle, cancellationToken).ConfigureAwait(false);
        }
        return entries;
    }

    /// <summary>Uploads bytes to a remote path, creating or truncating it.</summary>
    /// <param name="remotePath">The remote path.</param>
    /// <param name="content">The bytes to upload.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    public async ValueTask UploadAsync(string remotePath, ReadOnlyMemory<byte> content, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(remotePath);
        string handle = await OpenFileAsync(remotePath, SftpOpenFlags.Write | SftpOpenFlags.Create | SftpOpenFlags.Truncate, cancellationToken).ConfigureAwait(false);
        try
        {
            ulong offset = 0;
            int position = 0;
            while (position < content.Length)
            {
                int chunk = Math.Min(TransferChunkSize, content.Length - position);
                await WriteFileAsync(handle, offset, content.Slice(position, chunk), cancellationToken).ConfigureAwait(false);
                offset += (ulong)chunk;
                position += chunk;
            }
        }
        finally
        {
            await CloseHandleAsync(handle, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Downloads a remote file's full contents.</summary>
    /// <param name="remotePath">The remote path.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The file's bytes.</returns>
    public async ValueTask<byte[]> DownloadAsync(string remotePath, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(remotePath);
        string handle = await OpenFileAsync(remotePath, SftpOpenFlags.Read, cancellationToken).ConfigureAwait(false);
        using MemoryStream buffer = new MemoryStream();
        try
        {
            ulong offset = 0;
            while (true)
            {
                byte[] chunk = await ReadFileAsync(handle, offset, TransferChunkSize, cancellationToken).ConfigureAwait(false);
                if (chunk.Length == 0)
                {
                    break;
                }
                buffer.Write(chunk, 0, chunk.Length);
                offset += (ulong)chunk.Length;
            }
        }
        finally
        {
            await CloseHandleAsync(handle, cancellationToken).ConfigureAwait(false);
        }
        return buffer.ToArray();
    }

    private async ValueTask PathStatusAsync(SftpPacketType type, string path, bool withAttributes, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(path);
        uint id = NextId();
        using PooledBufferWriter payload = withAttributes ? BuildPathWithAttributes(id, path) : BuildPath(id, path);
        SftpResponse response = await ExchangeAsync(id, type, payload, cancellationToken).ConfigureAwait(false);
        ExpectOk(response);
    }

    private async ValueTask<SftpResponse> ExchangeAsync(uint id, SftpPacketType type, PooledBufferWriter payload, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        TaskCompletionSource<SftpResponse> completion = new TaskCompletionSource<SftpResponse>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pending[id] = completion;
        try
        {
            await SendAsync(type, payload.WrittenMemory, cancellationToken).ConfigureAwait(false);
            return await completion.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            _pending.TryRemove(id, out _);
            throw;
        }
    }

    private async ValueTask SendAsync(SftpPacketType type, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
    {
        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await _channel.WriteMessageAsync(type, payload, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private async Task ReadLoopAsync(CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                SftpResponse response;
                using (SftpMessage message = await _channel.ReadMessageAsync(cancellationToken).ConfigureAwait(false))
                {
                    response = SftpResponse.Parse(message);
                }
                if (_pending.TryRemove(response.Id, out TaskCompletionSource<SftpResponse>? completion))
                {
                    completion.TrySetResult(response);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Shutdown.
        }
        catch (Exception exception)
        {
            FaultPending(exception);
        }
    }

    private void FaultPending(Exception exception)
    {
        foreach (KeyValuePair<uint, TaskCompletionSource<SftpResponse>> entry in _pending)
        {
            if (_pending.TryRemove(entry.Key, out TaskCompletionSource<SftpResponse>? completion))
            {
                completion.TrySetException(exception);
            }
        }
    }

    private uint NextId()
    {
        return unchecked((uint)Interlocked.Increment(ref _nextRequestId));
    }

    private static string ExpectHandle(SftpResponse response)
    {
        if (response.Type != SftpPacketType.Handle || response.Handle == null)
        {
            throw ToException(response, "open");
        }
        return response.Handle;
    }

    private static void ExpectOk(SftpResponse response)
    {
        if (response.Type != SftpPacketType.Status)
        {
            throw new SftpException($"Expected a STATUS response but received {response.Type}.");
        }
        if (response.StatusCode != SftpStatusCode.Ok)
        {
            throw new SftpStatusException(response.StatusCode, response.StatusMessage);
        }
    }

    private static SftpException ToException(SftpResponse response, string operation)
    {
        if (response.Type == SftpPacketType.Status)
        {
            return new SftpStatusException(response.StatusCode, response.StatusMessage);
        }
        return new SftpException($"Unexpected {response.Type} response to {operation}.");
    }

    private static PooledBufferWriter BuildOpen(uint id, string path, SftpOpenFlags flags)
    {
        PooledBufferWriter writer = new PooledBufferWriter(32 + path.Length);
        SshWireWriter wire = new SshWireWriter(writer);
        wire.WriteUInt32(id);
        wire.WriteText(path);
        wire.WriteUInt32((uint)flags);
        new SftpFileAttributes().WriteTo(ref wire);
        return writer;
    }

    private static PooledBufferWriter BuildHandleRequest(uint id, string handle)
    {
        PooledBufferWriter writer = new PooledBufferWriter(16 + handle.Length);
        SshWireWriter wire = new SshWireWriter(writer);
        wire.WriteUInt32(id);
        wire.WriteString(Encoding.ASCII.GetBytes(handle));
        return writer;
    }

    private static PooledBufferWriter BuildRead(uint id, string handle, ulong offset, uint length)
    {
        PooledBufferWriter writer = new PooledBufferWriter(32 + handle.Length);
        SshWireWriter wire = new SshWireWriter(writer);
        wire.WriteUInt32(id);
        wire.WriteString(Encoding.ASCII.GetBytes(handle));
        wire.WriteUInt64(offset);
        wire.WriteUInt32(length);
        return writer;
    }

    private static PooledBufferWriter BuildWrite(uint id, string handle, ulong offset, ReadOnlySpan<byte> data)
    {
        PooledBufferWriter writer = new PooledBufferWriter(32 + handle.Length + data.Length);
        SshWireWriter wire = new SshWireWriter(writer);
        wire.WriteUInt32(id);
        wire.WriteString(Encoding.ASCII.GetBytes(handle));
        wire.WriteUInt64(offset);
        wire.WriteString(data);
        return writer;
    }

    private static PooledBufferWriter BuildPath(uint id, string path)
    {
        PooledBufferWriter writer = new PooledBufferWriter(16 + path.Length);
        SshWireWriter wire = new SshWireWriter(writer);
        wire.WriteUInt32(id);
        wire.WriteText(path);
        return writer;
    }

    private static PooledBufferWriter BuildPathWithAttributes(uint id, string path)
    {
        PooledBufferWriter writer = new PooledBufferWriter(24 + path.Length);
        SshWireWriter wire = new SshWireWriter(writer);
        wire.WriteUInt32(id);
        wire.WriteText(path);
        new SftpFileAttributes().WriteTo(ref wire);
        return writer;
    }

    private static PooledBufferWriter BuildRename(uint id, string oldPath, string newPath)
    {
        PooledBufferWriter writer = new PooledBufferWriter(24 + oldPath.Length + newPath.Length);
        SshWireWriter wire = new SshWireWriter(writer);
        wire.WriteUInt32(id);
        wire.WriteText(oldPath);
        wire.WriteText(newPath);
        return writer;
    }

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        _shutdown.Cancel();
        FaultPending(new SftpException("The SFTP client was disposed."));
        try
        {
            await _readerLoop.ConfigureAwait(false);
        }
        catch (Exception)
        {
            // Best-effort shutdown.
        }
        _shutdown.Dispose();
        _writeLock.Dispose();
    }

    private sealed class SftpResponse
    {
        private SftpResponse(SftpPacketType type, uint id)
        {
            Type = type;
            Id = id;
        }

        public SftpPacketType Type { get; }

        public uint Id { get; }

        public SftpStatusCode StatusCode { get; private set; }

        public string StatusMessage { get; private set; } = string.Empty;

        public string? Handle { get; private set; }

        public byte[] Data { get; private set; } = Array.Empty<byte>();

        public SftpFileAttributes? Attributes { get; private set; }

        public IReadOnlyList<SftpName> Names { get; private set; } = Array.Empty<SftpName>();

        public static SftpResponse Parse(SftpMessage message)
        {
            SshWireReader reader = message.CreateReader();
            SftpResponse response = new SftpResponse(message.Type, reader.ReadUInt32());
            switch (message.Type)
            {
                case SftpPacketType.Status:
                    response.StatusCode = (SftpStatusCode)reader.ReadUInt32();
                    response.StatusMessage = reader.ReadText();
                    break;
                case SftpPacketType.Handle:
                    response.Handle = Encoding.ASCII.GetString(reader.ReadString());
                    break;
                case SftpPacketType.Data:
                    response.Data = reader.ReadString().ToArray();
                    break;
                case SftpPacketType.Attrs:
                    response.Attributes = SftpFileAttributes.ReadFrom(ref reader);
                    break;
                case SftpPacketType.Name:
                    response.Names = ParseNames(ref reader);
                    break;
                default:
                    break;
            }
            return response;
        }

        private static IReadOnlyList<SftpName> ParseNames(ref SshWireReader reader)
        {
            uint count = reader.ReadUInt32();
            List<SftpName> names = new List<SftpName>((int)Math.Min(count, 4096));
            for (uint i = 0; i < count; i++)
            {
                string fileName = reader.ReadText();
                string longName = reader.ReadText();
                SftpFileAttributes attributes = SftpFileAttributes.ReadFrom(ref reader);
                names.Add(new SftpName(fileName, longName, attributes));
            }
            return names;
        }
    }
}
