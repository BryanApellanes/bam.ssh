using System.Text;
using Bam.Ssh.Connection;
using Bam.Ssh.Sftp;

namespace Bam.Ssh.Scp;

/// <summary>
/// Copies files and directory trees to and from a remote host over the classic SCP binary protocol. Each
/// transfer runs the remote <c>scp</c> program as its own <c>exec</c> channel (<c>scp -t</c> to upload,
/// <c>scp -f</c> to download) and speaks the C/D/E/T record protocol over it. The local side is an
/// <see cref="ISftpFileSystem"/>, so the same client transfers to and from an in-memory tree, a jailed OS
/// directory, or any other backing store.
/// </summary>
public sealed class ScpClient
{
    private readonly SshConnection _connection;

    /// <summary>
    /// Initializes the client over an authenticated connection.
    /// </summary>
    /// <param name="connection">The connection whose session channels carry the transfers.</param>
    /// <exception cref="ArgumentNullException">The connection is null.</exception>
    public ScpClient(SshConnection connection)
    {
        ArgumentNullException.ThrowIfNull(connection);
        _connection = connection;
    }

    /// <summary>
    /// Uploads a file or, recursively, a directory tree from the local filesystem to a remote path.
    /// </summary>
    /// <param name="localFileSystem">The local store the source is read from.</param>
    /// <param name="localPath">The source file or directory path in the local store.</param>
    /// <param name="remotePath">The remote destination path (passed to remote <c>scp -t</c>).</param>
    /// <param name="recursive">True to upload a directory tree; required when the source is a directory.</param>
    /// <param name="preserveTimes">True to send modification/access times.</param>
    /// <param name="cancellationToken">Cancels the transfer.</param>
    /// <exception cref="ArgumentNullException">A required argument is null.</exception>
    /// <exception cref="ScpException">The remote refused the exec or the transfer failed.</exception>
    public async Task UploadAsync(
        ISftpFileSystem localFileSystem,
        string localPath,
        string remotePath,
        bool recursive = false,
        bool preserveTimes = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(localFileSystem);
        ArgumentNullException.ThrowIfNull(localPath);
        ArgumentNullException.ThrowIfNull(remotePath);

        string command = BuildCommand("-t", recursive, preserveTimes, remotePath);
        SshSessionChannel channel = await _connection.OpenSessionChannelAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!await channel.ExecAsync(command, cancellationToken).ConfigureAwait(false))
            {
                throw new ScpException($"The remote host refused to start '{command}'.");
            }

            ScpProtocol protocol = new ScpProtocol(new SshChannelScpChannel(channel.Channel));
            ScpSender sender = new ScpSender(protocol, localFileSystem);
            await sender.SendAsync(localPath, recursive, preserveTimes, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            await CloseAsync(channel, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Downloads a file or, recursively, a directory tree from a remote path into the local filesystem.
    /// </summary>
    /// <param name="localFileSystem">The local store the download is written into.</param>
    /// <param name="remotePath">The remote source path (passed to remote <c>scp -f</c>).</param>
    /// <param name="localPath">The local destination path; if an existing directory, entries are placed inside it.</param>
    /// <param name="recursive">True to download a directory tree.</param>
    /// <param name="preserveTimes">True to request modification/access times from the remote source.</param>
    /// <param name="cancellationToken">Cancels the transfer.</param>
    /// <exception cref="ArgumentNullException">A required argument is null.</exception>
    /// <exception cref="ScpException">The remote refused the exec or the transfer failed.</exception>
    public async Task DownloadAsync(
        ISftpFileSystem localFileSystem,
        string remotePath,
        string localPath,
        bool recursive = false,
        bool preserveTimes = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(localFileSystem);
        ArgumentNullException.ThrowIfNull(remotePath);
        ArgumentNullException.ThrowIfNull(localPath);

        string command = BuildCommand("-f", recursive, preserveTimes, remotePath);
        SshSessionChannel channel = await _connection.OpenSessionChannelAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!await channel.ExecAsync(command, cancellationToken).ConfigureAwait(false))
            {
                throw new ScpException($"The remote host refused to start '{command}'.");
            }

            ScpProtocol protocol = new ScpProtocol(new SshChannelScpChannel(channel.Channel));
            ScpReceiver receiver = new ScpReceiver(protocol, localFileSystem);
            await receiver.ReceiveAsync(localPath, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            await CloseAsync(channel, cancellationToken).ConfigureAwait(false);
        }
    }

    private static async Task CloseAsync(SshSessionChannel channel, CancellationToken cancellationToken)
    {
        try
        {
            await channel.Channel.SendEofAsync(cancellationToken).ConfigureAwait(false);
            await channel.Channel.CloseAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (SshChannelException)
        {
            // The peer may have already closed the channel after finishing the transfer; that is benign.
        }
    }

    private static string BuildCommand(string modeFlag, bool recursive, bool preserveTimes, string remotePath)
    {
        StringBuilder builder = new StringBuilder("scp");
        if (recursive)
        {
            builder.Append(" -r");
        }

        if (preserveTimes)
        {
            builder.Append(" -p");
        }

        builder.Append(' ').Append(modeFlag).Append(' ').Append(QuotePath(remotePath));
        return builder.ToString();
    }

    private static string QuotePath(string path)
    {
        bool needsQuoting = false;
        foreach (char c in path)
        {
            if (char.IsWhiteSpace(c) || c == '\'' || c == '"' || c == '\\')
            {
                needsQuoting = true;
                break;
            }
        }

        if (!needsQuoting)
        {
            return path;
        }

        if (!path.Contains('"'))
        {
            return string.Concat("\"", path, "\"");
        }

        return string.Concat("'", path, "'");
    }
}
