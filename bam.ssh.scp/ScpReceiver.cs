using System.Buffers;
using System.Collections.Generic;
using Bam.Ssh.Sftp;

namespace Bam.Ssh.Scp;

/// <summary>
/// The SCP <em>sink</em> role: receives <c>C</c>/<c>D</c>/<c>E</c>/<c>T</c> records plus file data from the
/// peer and writes them into an <see cref="ISftpFileSystem"/>, following OpenSSH's directory-stack
/// placement. Reused on both ends — by the server's <c>scp -t</c> handler and by the client's download (peer
/// runs <c>scp -f</c>). The sink drives the start by sending the first acknowledgement.
/// </summary>
public sealed class ScpReceiver
{
    private const int ChunkSize = 32 * 1024;

    private readonly ScpProtocol _protocol;
    private readonly ISftpFileSystem _fileSystem;

    /// <summary>
    /// Initializes the receiver over a protocol helper and a backing filesystem.
    /// </summary>
    /// <param name="protocol">The byte-level SCP protocol over the channel.</param>
    /// <param name="fileSystem">The filesystem files are written into.</param>
    /// <exception cref="ArgumentNullException">Any argument is null.</exception>
    public ScpReceiver(ScpProtocol protocol, ISftpFileSystem fileSystem)
    {
        ArgumentNullException.ThrowIfNull(protocol);
        ArgumentNullException.ThrowIfNull(fileSystem);
        _protocol = protocol;
        _fileSystem = fileSystem;
    }

    /// <summary>
    /// Receives a file or directory tree from the peer into <paramref name="targetPath"/>. If the target is
    /// an existing directory, incoming entries are placed inside it by name; otherwise a single top-level
    /// file or directory is written as the target itself (the classic scp rename).
    /// </summary>
    /// <param name="targetPath">The destination path in the filesystem.</param>
    /// <param name="cancellationToken">Cancels the transfer.</param>
    /// <exception cref="ScpException">A record was malformed or the peer errored.</exception>
    public async Task ReceiveAsync(string targetPath, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(targetPath);
        await _protocol.WriteAckAsync(cancellationToken).ConfigureAwait(false);

        bool targetIsDirectory = await IsDirectoryAsync(targetPath, cancellationToken).ConfigureAwait(false);
        string canonicalTarget = SftpPath.Canonicalize(targetPath);
        Stack<string> directoryStack = new Stack<string>();
        string currentDirectory = targetIsDirectory ? canonicalTarget : SftpPath.GetParent(canonicalTarget);
        long? pendingModifyTime = null;
        long? pendingAccessTime = null;

        while (true)
        {
            string? line = await _protocol.ReadControlLineAsync(cancellationToken).ConfigureAwait(false);
            if (line is null)
            {
                break;
            }

            // A source that fails mid-transfer sends an error record (0x01 warning / 0x02 fatal) in place of
            // the next control line; surface its message rather than mis-parsing the opcode byte.
            if (line.Length > 0 && (line[0] == '' || line[0] == ''))
            {
                throw new ScpException($"The SCP source reported an error: {line.Substring(1)}");
            }

            ScpControlMessage message = ScpControlMessage.Parse(line);
            switch (message.Type)
            {
                case ScpControlType.Time:
                    pendingModifyTime = message.ModifyTime;
                    pendingAccessTime = message.AccessTime;
                    await _protocol.WriteAckAsync(cancellationToken).ConfigureAwait(false);
                    break;

                case ScpControlType.Directory:
                {
                    bool atTopLevel = directoryStack.Count == 0;
                    string directoryPath = atTopLevel && !targetIsDirectory
                        ? canonicalTarget
                        : Join(currentDirectory, message.Name);
                    await EnsureDirectoryAsync(directoryPath, message.Mode, cancellationToken).ConfigureAwait(false);
                    await ApplyPendingTimesAsync(directoryPath, pendingModifyTime, pendingAccessTime, cancellationToken).ConfigureAwait(false);
                    pendingModifyTime = null;
                    pendingAccessTime = null;
                    directoryStack.Push(currentDirectory);
                    currentDirectory = directoryPath;
                    await _protocol.WriteAckAsync(cancellationToken).ConfigureAwait(false);
                    break;
                }

                case ScpControlType.EndDirectory:
                    if (directoryStack.Count > 0)
                    {
                        currentDirectory = directoryStack.Pop();
                    }

                    await _protocol.WriteAckAsync(cancellationToken).ConfigureAwait(false);
                    break;

                case ScpControlType.File:
                {
                    bool atTopLevel = directoryStack.Count == 0;
                    string filePath = atTopLevel && !targetIsDirectory
                        ? canonicalTarget
                        : Join(currentDirectory, message.Name);
                    await ReceiveFileAsync(filePath, message, cancellationToken).ConfigureAwait(false);
                    await ApplyPendingTimesAsync(filePath, pendingModifyTime, pendingAccessTime, cancellationToken).ConfigureAwait(false);
                    pendingModifyTime = null;
                    pendingAccessTime = null;
                    break;
                }

                default:
                    throw new ScpException($"Unexpected SCP record type {message.Type}.");
            }
        }
    }

    private async Task ReceiveFileAsync(string filePath, ScpControlMessage message, CancellationToken cancellationToken)
    {
        SftpFileAttributes attributes = new SftpFileAttributes(permissions: (message.Mode & 0xFFF) | SftpConstants.ModeRegularFile);
        ISftpFileHandle handle = await _fileSystem.OpenFileAsync(
            filePath,
            SftpOpenFlags.Create | SftpOpenFlags.Write | SftpOpenFlags.Truncate,
            attributes,
            cancellationToken).ConfigureAwait(false);

        // Acknowledge the C record so the source begins streaming the data.
        await _protocol.WriteAckAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            byte[] buffer = ArrayPool<byte>.Shared.Rent(ChunkSize);
            try
            {
                ulong offset = 0;
                long remaining = message.Size;
                while (remaining > 0)
                {
                    int want = (int)Math.Min(remaining, buffer.Length);
                    await _protocol.ReadExactAsync(buffer.AsMemory(0, want), cancellationToken).ConfigureAwait(false);
                    await handle.WriteAsync(offset, buffer.AsMemory(0, want), cancellationToken).ConfigureAwait(false);
                    offset += (ulong)want;
                    remaining -= want;
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

        // Read the source's trailing status byte, then acknowledge the completed file.
        await _protocol.ReadAckAsync(cancellationToken).ConfigureAwait(false);
        await _protocol.WriteAckAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task EnsureDirectoryAsync(string path, uint mode, CancellationToken cancellationToken)
    {
        SftpFileAttributes attributes = new SftpFileAttributes(permissions: (mode & 0xFFF) | SftpConstants.ModeDirectory);
        try
        {
            await _fileSystem.MakeDirectoryAsync(path, attributes, cancellationToken).ConfigureAwait(false);
        }
        catch (SftpStatusException)
        {
            // The directory may already exist (a recursive copy into an existing tree). Accept it if so.
            if (!await IsDirectoryAsync(path, cancellationToken).ConfigureAwait(false))
            {
                throw;
            }
        }
    }

    private async Task ApplyPendingTimesAsync(string path, long? modifyTime, long? accessTime, CancellationToken cancellationToken)
    {
        if (modifyTime is null && accessTime is null)
        {
            return;
        }

        SftpFileAttributes attributes = new SftpFileAttributes(
            accessTime: accessTime is long a ? (uint)a : null,
            modifyTime: modifyTime is long m ? (uint)m : null);
        try
        {
            await _fileSystem.SetAttributesAsync(path, attributes, cancellationToken).ConfigureAwait(false);
        }
        catch (SftpStatusException)
        {
            // Timestamps are best-effort; a filesystem that cannot set them does not fail the transfer.
        }
    }

    private async Task<bool> IsDirectoryAsync(string path, CancellationToken cancellationToken)
    {
        try
        {
            SftpFileAttributes attributes = await _fileSystem.GetAttributesAsync(path, followSymbolicLinks: true, cancellationToken).ConfigureAwait(false);
            return attributes.IsDirectory;
        }
        catch (SftpStatusException)
        {
            return false;
        }
    }

    private static string Join(string parent, string name)
    {
        return SftpPath.Canonicalize(string.Concat(parent, "/", name));
    }
}
