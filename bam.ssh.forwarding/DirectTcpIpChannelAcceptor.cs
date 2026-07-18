using System.Net.Sockets;
using Bam.Ssh.Connection;

namespace Bam.Ssh.Forwarding;

/// <summary>
/// Handles inbound <c>direct-tcpip</c> channel opens — the connect side of a peer's local or dynamic
/// forwarding. Registered on an <see cref="SshConnection"/> (typically a server's), it accepts the channel,
/// connects a TCP socket to the requested target, and bridges the two. An optional
/// <see cref="SshForwardingTargetFilter"/> vetoes disallowed targets. Because the handler runs on the
/// connection's dispatch loop it must not block: it accepts synchronously and connects off the loop, so a
/// connect failure surfaces as an immediate channel close rather than an open failure.
/// </summary>
public sealed class DirectTcpIpChannelAcceptor : ISshChannelOpenHandler
{
    private readonly SshConnectionOptions _options;
    private readonly SshForwardingTargetFilter? _targetFilter;

    /// <summary>
    /// Initializes the acceptor.
    /// </summary>
    /// <param name="options">The connection options (window/packet sizes for accepted channels).</param>
    /// <param name="targetFilter">An optional policy that vetoes disallowed connect targets.</param>
    /// <exception cref="ArgumentNullException">The options are null.</exception>
    public DirectTcpIpChannelAcceptor(SshConnectionOptions options, SshForwardingTargetFilter? targetFilter = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options;
        _targetFilter = targetFilter;
    }

    /// <inheritdoc/>
    public ValueTask HandleOpenAsync(SshChannelOpenRequestContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        DirectTcpIpChannelRequest request;
        try
        {
            request = DirectTcpIpChannelRequest.Parse(context.TypeSpecificData.Span);
        }
        catch (SshForwardingException)
        {
            context.Reject(SshChannelOpenFailureReason.ConnectFailed, "Malformed direct-tcpip request.");
            return ValueTask.CompletedTask;
        }

        if (_targetFilter != null && !_targetFilter(request.Host, request.Port))
        {
            context.Reject(SshChannelOpenFailureReason.AdministrativelyProhibited, "Forwarding to the requested target is not allowed.");
            return ValueTask.CompletedTask;
        }

        SshChannel channel = context.Accept();
        _ = ConnectAndBridgeAsync(channel, request, cancellationToken);
        return ValueTask.CompletedTask;
    }

    private static async Task ConnectAndBridgeAsync(SshChannel channel, DirectTcpIpChannelRequest request, CancellationToken cancellationToken)
    {
        Socket socket;
        try
        {
            socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
            await socket.ConnectAsync(request.Host, request.Port, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // The target was unreachable; close the channel so the client's forwarder tears its socket down.
            try
            {
                await channel.CloseAsync(CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception)
            {
                // Best-effort.
            }
            return;
        }

        await SshChannelSocketBridge.RunAsync(socket, channel, cancellationToken).ConfigureAwait(false);
    }
}
