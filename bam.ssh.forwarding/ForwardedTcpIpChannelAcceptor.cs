using System.Collections.Concurrent;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using Bam.Ssh.Connection;

namespace Bam.Ssh.Forwarding;

/// <summary>
/// Handles inbound <c>forwarded-tcpip</c> channel opens on the client side of remote (<c>-R</c>) forwarding:
/// when a connection arrives on a server-bound port, the server opens this channel and the acceptor connects
/// to the matching local target and bridges. One acceptor is shared per <see cref="SshConnection"/> (only one
/// handler may be registered for a channel type), routing by the forwarded port so several
/// <see cref="RemotePortForwarder"/>s on the same connection coexist.
/// </summary>
internal sealed class ForwardedTcpIpChannelAcceptor : ISshChannelOpenHandler
{
    private static readonly ConditionalWeakTable<SshConnection, ForwardedTcpIpChannelAcceptor> Registry =
        new ConditionalWeakTable<SshConnection, ForwardedTcpIpChannelAcceptor>();
    private static readonly object RegistryLock = new object();

    private readonly ConcurrentDictionary<int, RemoteForwardBinding> _bindings =
        new ConcurrentDictionary<int, RemoteForwardBinding>();

    private ForwardedTcpIpChannelAcceptor()
    {
    }

    public static ForwardedTcpIpChannelAcceptor GetOrCreate(SshConnection connection)
    {
        ArgumentNullException.ThrowIfNull(connection);
        lock (RegistryLock)
        {
            if (!Registry.TryGetValue(connection, out ForwardedTcpIpChannelAcceptor? acceptor))
            {
                acceptor = new ForwardedTcpIpChannelAcceptor();
                Registry.Add(connection, acceptor);
                connection.RegisterChannelOpenHandler(SshForwardingNames.ForwardedTcpIp, acceptor);
            }
            return acceptor;
        }
    }

    public void AddBinding(int forwardedPort, string localHost, int localPort, SshConnectionOptions options)
    {
        _bindings[forwardedPort] = new RemoteForwardBinding(localHost, localPort, options);
    }

    public void RemoveBinding(int forwardedPort)
    {
        _bindings.TryRemove(forwardedPort, out _);
    }

    public ValueTask HandleOpenAsync(SshChannelOpenRequestContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        ForwardedTcpIpChannelInfo info;
        try
        {
            info = ForwardedTcpIpChannelInfo.Parse(context.TypeSpecificData.Span);
        }
        catch (SshForwardingException)
        {
            context.Reject(SshChannelOpenFailureReason.ConnectFailed, "Malformed forwarded-tcpip request.");
            return ValueTask.CompletedTask;
        }

        if (!_bindings.TryGetValue(info.ConnectedPort, out RemoteForwardBinding? binding))
        {
            context.Reject(SshChannelOpenFailureReason.AdministrativelyProhibited, "No remote forward is registered for this port.");
            return ValueTask.CompletedTask;
        }

        SshChannel channel = context.Accept();
        _ = ConnectAndBridgeAsync(channel, binding, cancellationToken);
        return ValueTask.CompletedTask;
    }

    private static async Task ConnectAndBridgeAsync(SshChannel channel, RemoteForwardBinding binding, CancellationToken cancellationToken)
    {
        Socket socket;
        try
        {
            socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
            await socket.ConnectAsync(binding.LocalHost, binding.LocalPort, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception)
        {
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

    private sealed class RemoteForwardBinding
    {
        public RemoteForwardBinding(string localHost, int localPort, SshConnectionOptions options)
        {
            LocalHost = localHost;
            LocalPort = localPort;
            Options = options;
        }

        public string LocalHost { get; }

        public int LocalPort { get; }

        public SshConnectionOptions Options { get; }
    }
}
