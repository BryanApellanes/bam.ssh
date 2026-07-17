using Bam.Ssh.Connection;

namespace Bam.Ssh.Sftp;

/// <summary>
/// Adapts an <see cref="SshChannel"/>'s data stream to the SFTP byte-channel seam: reads are the channel's
/// inbound data and writes are its outbound data. Used by the client to run SFTP over a session channel that
/// has started the <c>sftp</c> subsystem.
/// </summary>
public sealed class SshChannelSftpChannel : ISftpChannel
{
    private readonly SshChannel _channel;

    /// <summary>
    /// Initializes the adapter over a channel.
    /// </summary>
    /// <param name="channel">The channel whose data stream carries SFTP.</param>
    /// <exception cref="ArgumentNullException">The channel is null.</exception>
    public SshChannelSftpChannel(SshChannel channel)
    {
        ArgumentNullException.ThrowIfNull(channel);
        _channel = channel;
    }

    /// <inheritdoc/>
    public ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        return _channel.ReadAsync(buffer, cancellationToken);
    }

    /// <inheritdoc/>
    public ValueTask WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
    {
        return _channel.WriteAsync(data, cancellationToken);
    }
}
