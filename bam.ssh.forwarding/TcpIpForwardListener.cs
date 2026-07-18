using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Bam.Ssh.Connection;

namespace Bam.Ssh.Forwarding;

/// <summary>
/// The listen side of remote (<c>-R</c>) forwarding, typically a server's: handles <c>tcpip-forward</c> by
/// binding a TCP listener and, for each accepted connection, opening a <c>forwarded-tcpip</c> channel back to
/// the peer and bridging; handles <c>cancel-tcpip-forward</c> by stopping the matching listener. One listener
/// serves one <see cref="SshConnection"/>; register it for both request names. An optional
/// <see cref="SshForwardingBindFilter"/> vetoes disallowed binds. The request handler runs on the dispatch
/// loop, so it only binds (fast) and spawns the accept loop off the loop.
/// </summary>
public sealed class TcpIpForwardListener : ISshGlobalRequestHandler, IAsyncDisposable
{
    private readonly SshConnection _connection;
    private readonly SshConnectionOptions _options;
    private readonly SshForwardingBindFilter? _bindFilter;
    private readonly ConcurrentDictionary<int, Binding> _bindings = new ConcurrentDictionary<int, Binding>();
    private readonly CancellationTokenSource _cancellation = new CancellationTokenSource();
    private bool _disposed;

    /// <summary>
    /// Initializes the listener.
    /// </summary>
    /// <param name="connection">The connection to open <c>forwarded-tcpip</c> channels on.</param>
    /// <param name="options">The connection options (window/packet sizes for opened channels).</param>
    /// <param name="bindFilter">An optional policy that vetoes disallowed binds.</param>
    /// <exception cref="ArgumentNullException">The connection or options are null.</exception>
    public TcpIpForwardListener(SshConnection connection, SshConnectionOptions options, SshForwardingBindFilter? bindFilter = null)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(options);
        _connection = connection;
        _options = options;
        _bindFilter = bindFilter;
    }

    /// <inheritdoc/>
    public ValueTask HandleRequestAsync(SshGlobalRequestContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        switch (context.RequestName)
        {
            case SshForwardingNames.TcpIpForward:
                HandleForward(context);
                break;
            case SshForwardingNames.CancelTcpIpForward:
                HandleCancel(context);
                break;
            default:
                context.Reject();
                break;
        }
        return ValueTask.CompletedTask;
    }

    private void HandleForward(SshGlobalRequestContext context)
    {
        if (_disposed)
        {
            context.Reject();
            return;
        }

        TcpIpForwardRequest request;
        try
        {
            request = TcpIpForwardRequest.Parse(context.RequestData.Span);
        }
        catch (SshForwardingException)
        {
            context.Reject();
            return;
        }

        if (_bindFilter != null && !_bindFilter(request.BindAddress, request.BindPort))
        {
            context.Reject();
            return;
        }

        Socket listener;
        int boundPort;
        try
        {
            IPAddress address = ResolveBindAddress(request.BindAddress);
            listener = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            listener.Bind(new IPEndPoint(address, request.BindPort));
            listener.Listen(128);
            boundPort = ((IPEndPoint)listener.LocalEndPoint!).Port;
        }
        catch (SocketException)
        {
            context.Reject();
            return;
        }

        Binding binding = new Binding(listener, request.BindAddress, boundPort);
        if (!_bindings.TryAdd(boundPort, binding))
        {
            listener.Dispose();
            context.Reject();
            return;
        }

        binding.AcceptLoop = AcceptLoopAsync(binding, _cancellation.Token);
        // Only a request that asked for port 0 receives the bound port in its reply (RFC 4254 §7.1).
        context.Accept(request.BindPort == 0 ? TcpIpForwardRequest.BuildBoundPortReply(boundPort) : ReadOnlyMemory<byte>.Empty);
    }

    private void HandleCancel(SshGlobalRequestContext context)
    {
        TcpIpForwardRequest request;
        try
        {
            request = TcpIpForwardRequest.Parse(context.RequestData.Span);
        }
        catch (SshForwardingException)
        {
            context.Reject();
            return;
        }

        if (_bindings.TryRemove(request.BindPort, out Binding? binding))
        {
            binding.Listener.Dispose();
            context.Accept();
        }
        else
        {
            context.Reject();
        }
    }

    private async Task AcceptLoopAsync(Binding binding, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            Socket socket;
            try
            {
                socket = await binding.Listener.AcceptAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (SocketException)
            {
                break;
            }
            _ = HandleConnectionAsync(binding, socket, cancellationToken);
        }
    }

    private async Task HandleConnectionAsync(Binding binding, Socket socket, CancellationToken cancellationToken)
    {
        SshChannel channel;
        try
        {
            IPEndPoint originator = (IPEndPoint)socket.RemoteEndPoint!;
            ForwardedTcpIpChannelInfo info = new ForwardedTcpIpChannelInfo(
                binding.BindAddress, binding.BoundPort, originator.Address.ToString(), originator.Port);
            channel = await _connection.OpenChannelAsync(info.ToChannelOpenParameters(_options), cancellationToken).ConfigureAwait(false);
        }
        catch (Exception)
        {
            try
            {
                socket.Dispose();
            }
            catch (Exception)
            {
                // Best-effort.
            }
            return;
        }

        await SshChannelSocketBridge.RunAsync(socket, channel, cancellationToken).ConfigureAwait(false);
    }

    private static IPAddress ResolveBindAddress(string bindAddress)
    {
        if (string.IsNullOrEmpty(bindAddress) || bindAddress == "*" || bindAddress == "0.0.0.0")
        {
            return IPAddress.Any;
        }
        if (bindAddress == "::")
        {
            return IPAddress.IPv6Any;
        }
        if (string.Equals(bindAddress, "localhost", StringComparison.OrdinalIgnoreCase))
        {
            return IPAddress.Loopback;
        }
        if (IPAddress.TryParse(bindAddress, out IPAddress? parsed))
        {
            return parsed;
        }
        // An unresolvable bind address falls back to all interfaces rather than failing the forward.
        return IPAddress.Any;
    }

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        _cancellation.Cancel();
        List<Task> loops = new List<Task>();
        foreach (Binding binding in _bindings.Values)
        {
            binding.Listener.Dispose();
            loops.Add(binding.AcceptLoop);
        }
        _bindings.Clear();
        try
        {
            await Task.WhenAll(loops).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // Best-effort drain.
        }
        _cancellation.Dispose();
    }

    private sealed class Binding
    {
        public Binding(Socket listener, string bindAddress, int boundPort)
        {
            Listener = listener;
            BindAddress = bindAddress;
            BoundPort = boundPort;
        }

        public Socket Listener { get; }

        public string BindAddress { get; }

        public int BoundPort { get; }

        public Task AcceptLoop { get; set; } = Task.CompletedTask;
    }
}
