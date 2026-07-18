using Bam.Ssh.Connection;
using Bam.Ssh.Forwarding;

namespace Bam.Ssh.Server;

/// <summary>
/// Wires TCP/IP forwarding into one authenticated peer connection: registers a
/// <see cref="DirectTcpIpChannelAcceptor"/> for the connect side of the peer's local/dynamic forwarding and a
/// <see cref="TcpIpForwardListener"/> for the listen side of the peer's remote forwarding, according to the
/// server's <see cref="SshForwardingOptions"/>. Owned by the <see cref="SshServerSession"/> and disposed with
/// it, tearing down any listeners the peer requested.
/// </summary>
public sealed class SshServerForwarding : IAsyncDisposable
{
    private readonly TcpIpForwardListener? _remoteListener;

    /// <summary>
    /// Registers the enabled forwarding handlers on the connection.
    /// </summary>
    /// <param name="connection">The peer connection to service.</param>
    /// <param name="options">The connection options (window/packet sizes for forwarding channels).</param>
    /// <param name="forwardingOptions">Which forwarding to allow and the gating policies.</param>
    /// <exception cref="ArgumentNullException">Any argument is null.</exception>
    public SshServerForwarding(SshConnection connection, SshConnectionOptions options, SshForwardingOptions forwardingOptions)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(forwardingOptions);

        if (forwardingOptions.AllowLocalForwarding)
        {
            DirectTcpIpChannelAcceptor acceptor = new DirectTcpIpChannelAcceptor(options, forwardingOptions.TargetFilter);
            connection.RegisterChannelOpenHandler(SshForwardingNames.DirectTcpIp, acceptor);
        }

        if (forwardingOptions.AllowRemoteForwarding)
        {
            _remoteListener = new TcpIpForwardListener(connection, options, forwardingOptions.BindFilter);
            connection.RegisterGlobalRequestHandler(SshForwardingNames.TcpIpForward, _remoteListener);
            connection.RegisterGlobalRequestHandler(SshForwardingNames.CancelTcpIpForward, _remoteListener);
        }
    }

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        if (_remoteListener != null)
        {
            await _remoteListener.DisposeAsync().ConfigureAwait(false);
        }
    }
}
