using System.Buffers;
using System.Collections.Generic;
using Bam.Ssh.Sftp;

namespace Bam.Ssh.Scp;

/// <summary>
/// The SCP <em>source</em> role: streams a file or, recursively, a directory tree from an
/// <see cref="ISftpFileSystem"/> to the peer as <c>C</c>/<c>D</c>/<c>E</c> records plus file data. Reused on
/// both ends — by the client's upload (peer runs <c>scp -t</c>) and by the server's <c>scp -f</c> handler —
/// because the source role is identical regardless of which side plays it. The sink always sends the first
/// acknowledgement, so the source reads it before sending anything.
/// </summary>
public sealed class ScpSender
{
    private const int ChunkSize = 32 * 1024;

    private readonly ScpProtocol _protocol;
    private readonly ISftpFileSystem _fileSystem;

    /// <summary>
    /// Initializes the sender over a protocol helper and a backing filesystem.
    /// </summary>
    /// <param name="protocol">The byte-level SCP protocol over the channel.</param>
    /// <param name="fileSystem">The filesystem the files are read from.</param>
    /// <exception cref="ArgumentNullException">Any argument is null.</exception>
    public ScpSender(ScpProtocol protocol, ISftpFileSystem fileSystem)
    {
        ArgumentNullException.ThrowIfNull(protocol);
        ArgumentNullException.ThrowIfNull(fileSystem);
        _protocol = protocol;
        _fileSystem = fileSystem;
    }

    /// <summary>
    /// Sends the file or directory tree at <paramref name="path"/> to the peer.
    /// </summary>
    /// <param name="path">The source path in the filesystem.</param>
    /// <param name="recursive">True to descend into directories; a directory path with this false is an error.</param>
    /// <param name="preserveTimes">True to precede each entry with a <c>T</c> timestamps record.</param>
    /// <param name="cancellationToken">Cancels the transfer.</param>
    /// <exception cref="ScpException">The path is a directory but recursion was not requested, or the peer errored.</exception>
    public async Task SendAsync(string path, bool recursive, bool preserveTimes, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(path);
        await _protocol.ReadAckAsync(cancellationToken).ConfigureAwait(false);
        string name = SftpPath.GetFileName(path);
        await SendEntryAsync(path, name, recursive, preserveTimes, cancellationToken).ConfigureAwait(false);
    }

    private async Task SendEntryAsync(string path, string name, bool recursive, bool preserveTimes, CancellationToken cancellationToken)
    {
        SftpFileAttributes attributes = await _fileSystem.GetAttributesAsync(path, followSymbolicLinks: true, cancellationToken).ConfigureAwait(false);
        if (attributes.IsDirectory)
        {
            if (!recursive)
            {
                throw new ScpException($"'{path}' is a directory; recursive transfer was not requested.");
            }

            await SendDirectoryAsync(path, name, attributes, preserveTimes, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            await SendFileAsync(path, name, attributes, preserveTimes, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task SendFileAsync(string path, string name, SftpFileAttributes attributes, bool preserveTimes, CancellationToken cancellationToken)
    {
        if (preserveTimes)
        {
            await SendTimesAsync(attributes, cancellationToken).ConfigureAwait(false);
        }

        long size = (long)(attributes.Size ?? 0);
        uint mode = attributes.Permissions ?? SftpConstants.DefaultFilePermissions;
        await _protocol.WriteLineAsync(ScpControlMessage.FormatFile(mode, size, name), cancellationToken).ConfigureAwait(false);
        await _protocol.ReadAckAsync(cancellationToken).ConfigureAwait(false);

        ISftpFileHandle handle = await _fileSystem.OpenFileAsync(path, SftpOpenFlags.Read, new SftpFileAttributes(), cancellationToken).ConfigureAwait(false);
        try
        {
            byte[] buffer = ArrayPool<byte>.Shared.Rent(ChunkSize);
            try
            {
                ulong offset = 0;
                long remaining = size;
                while (remaining > 0)
                {
                    int want = (int)Math.Min(remaining, buffer.Length);
                    int read = await handle.ReadAsync(offset, buffer.AsMemory(0, want), cancellationToken).ConfigureAwait(false);
                    if (read <= 0)
                    {
                        throw new ScpException($"'{path}' ended after {(long)offset} of {size} bytes.");
                    }

                    await _protocol.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                    offset += (ulong)read;
                    remaining -= read;
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }
        finally
        {
            await handle.DisposeAsync().ConfigureAwait(false);
        }

        // The trailing zero byte signals a clean end of the file's data; the sink then acknowledges the file.
        await _protocol.WriteAckAsync(cancellationToken).ConfigureAwait(false);
        await _protocol.ReadAckAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task SendDirectoryAsync(string path, string name, SftpFileAttributes attributes, bool preserveTimes, CancellationToken cancellationToken)
    {
        if (preserveTimes)
        {
            await SendTimesAsync(attributes, cancellationToken).ConfigureAwait(false);
        }

        uint mode = attributes.Permissions ?? SftpConstants.DefaultDirectoryPermissions;
        await _protocol.WriteLineAsync(ScpControlMessage.FormatDirectory(mode, name), cancellationToken).ConfigureAwait(false);
        await _protocol.ReadAckAsync(cancellationToken).ConfigureAwait(false);

        IReadOnlyList<string> childNames = await ListChildNamesAsync(path, cancellationToken).ConfigureAwait(false);
        foreach (string childName in childNames)
        {
            string childPath = Join(path, childName);
            await SendEntryAsync(childPath, childName, recursive: true, preserveTimes, cancellationToken).ConfigureAwait(false);
        }

        await _protocol.WriteLineAsync(ScpControlMessage.EndDirectoryLine, cancellationToken).ConfigureAwait(false);
        await _protocol.ReadAckAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task SendTimesAsync(SftpFileAttributes attributes, CancellationToken cancellationToken)
    {
        long modifyTime = attributes.ModifyTime ?? 0;
        long accessTime = attributes.AccessTime ?? modifyTime;
        await _protocol.WriteLineAsync(ScpControlMessage.FormatTime(modifyTime, accessTime), cancellationToken).ConfigureAwait(false);
        await _protocol.ReadAckAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task<IReadOnlyList<string>> ListChildNamesAsync(string path, CancellationToken cancellationToken)
    {
        List<string> names = new List<string>();
        ISftpDirectoryHandle directory = await _fileSystem.OpenDirectoryAsync(path, cancellationToken).ConfigureAwait(false);
        try
        {
            while (true)
            {
                IReadOnlyList<SftpName> batch = await directory.ReadAsync(cancellationToken).ConfigureAwait(false);
                if (batch.Count == 0)
                {
                    break;
                }

                foreach (SftpName entry in batch)
                {
                    if (entry.FileName == "." || entry.FileName == "..")
                    {
                        continue;
                    }

                    names.Add(entry.FileName);
                }
            }
        }
        finally
        {
            await directory.DisposeAsync().ConfigureAwait(false);
        }

        return names;
    }

    private static string Join(string parent, string name)
    {
        return SftpPath.Canonicalize(string.Concat(parent, "/", name));
    }
}
