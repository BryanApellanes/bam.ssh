using Bam.Ssh.Connection;

namespace Bam.Ssh.Scp;

/// <summary>
/// Adapts an <see cref="SshChannel"/>'s data stream to the SCP byte-channel seam: reads are the channel's
/// inbound data and writes are its outbound data. Used by <see cref="ScpClient"/> to run SCP over a session
/// channel that has started a remote <c>scp -t</c>/<c>scp -f</c> via <c>exec</c>.
/// </summary>
public sealed class SshChannelScpChannel : IScpChannel
{
    private readonly SshChannel _channel;

    /// <summary>
    /// Initializes the adapter over a channel.
    /// </summary>
    /// <param name="channel">The channel whose data stream carries the SCP protocol.</param>
    /// <exception cref="ArgumentNullException">The channel is null.</exception>
    public SshChannelScpChannel(SshChannel channel)
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
