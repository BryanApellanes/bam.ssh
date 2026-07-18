using System.Net;
using System.Net.Sockets;
using Bam.Ssh.Connection;

namespace Bam.Ssh.Forwarding;

/// <summary>
/// Local (<c>-L</c>) port forwarding: binds a local TCP listener and, for each accepted connection, opens a
/// <c>direct-tcpip</c> channel asking the server to connect to a fixed remote target, then bridges the socket
/// and channel. The listener runs until the forwarder is disposed.
/// </summary>
public sealed class LocalPortForwarder : IAsyncDisposable
{
    private readonly SshConnection _connection;
    private readonly IPEndPoint _bindEndPoint;
    private readonly string _remoteHost;
    private readonly int _remotePort;
    private readonly SshConnectionOptions _options;

    private Socket? _listener;
    private CancellationTokenSource? _cancellation;
    private Task _acceptLoop = Task.CompletedTask;
    private bool _disposed;

    /// <summary>
    /// Initializes the forwarder.
    /// </summary>
    /// <param name="connection">The authenticated connection to tunnel over.</param>
    /// <param name="bindEndPoint">The local endpoint to listen on (use port 0 for an ephemeral port).</param>
    /// <param name="remoteHost">The host the server should connect to.</param>
    /// <param name="remotePort">The port the server should connect to.</param>
    /// <param name="options">Connection options for opened channels; defaults to the connection defaults.</param>
    /// <exception cref="ArgumentNullException">The connection, endpoint, or remote host is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The remote port is outside 0–65535.</exception>
    public LocalPortForwarder(SshConnection connection, IPEndPoint bindEndPoint, string remoteHost, int remotePort, SshConnectionOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(bindEndPoint);
        ArgumentException.ThrowIfNullOrEmpty(remoteHost);
        ForwardingPort.Validate(remotePort);
        _connection = connection;
        _bindEndPoint = bindEndPoint;
        _remoteHost = remoteHost;
        _remotePort = remotePort;
        _options = options ?? SshConnectionOptions.Default;
    }

    /// <summary>
    /// Gets the endpoint the forwarder is listening on, or null before <see cref="StartAsync"/>.
    /// </summary>
    public IPEndPoint? ListenEndPoint => _listener?.LocalEndPoint as IPEndPoint;

    /// <summary>
    /// Binds the local listener and starts accepting connections in the background.
    /// </summary>
    /// <param name="cancellationToken">Cancels the bind.</param>
    /// <exception cref="SshForwardingException">The local endpoint could not be bound.</exception>
    public ValueTask StartAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        cancellationToken.ThrowIfCancellationRequested();
        Socket listener = new Socket(_bindEndPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            listener.Bind(_bindEndPoint);
            listener.Listen(128);
        }
        catch (SocketException exception)
        {
            listener.Dispose();
            throw new SshForwardingException($"Failed to bind the local forward endpoint {_bindEndPoint}: {exception.Message}", exception);
        }

        _listener = listener;
        _cancellation = new CancellationTokenSource();
        _acceptLoop = AcceptLoopAsync(_cancellation.Token);
        return ValueTask.CompletedTask;
    }

    private async Task AcceptLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            Socket socket;
            try
            {
                socket = await _listener!.AcceptAsync(cancellationToken).ConfigureAwait(false);
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
            _ = HandleAcceptedAsync(socket, cancellationToken);
        }
    }

    private async Task HandleAcceptedAsync(Socket socket, CancellationToken cancellationToken)
    {
        SshChannel channel;
        try
        {
            IPEndPoint originator = (IPEndPoint)socket.RemoteEndPoint!;
            DirectTcpIpChannelRequest request = new DirectTcpIpChannelRequest(
                _remoteHost, _remotePort, originator.Address.ToString(), originator.Port);
            channel = await _connection.OpenChannelAsync(request.ToChannelOpenParameters(_options), cancellationToken).ConfigureAwait(false);
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

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        _cancellation?.Cancel();
        _listener?.Dispose();
        try
        {
            await _acceptLoop.ConfigureAwait(false);
        }
        catch (Exception)
        {
            // Best-effort drain.
        }
        _cancellation?.Dispose();
    }
}
