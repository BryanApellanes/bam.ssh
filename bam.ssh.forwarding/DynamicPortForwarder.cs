using System.Net;
using System.Net.Sockets;
using Bam.Ssh.Connection;

namespace Bam.Ssh.Forwarding;

/// <summary>
/// Dynamic (<c>-D</c>) port forwarding: binds a local SOCKS proxy and, for each accepted connection,
/// negotiates the destination (SOCKS5 no-auth or SOCKS4/4a CONNECT), opens a <c>direct-tcpip</c> channel to
/// that destination, and bridges. The listener runs until the forwarder is disposed.
/// </summary>
public sealed class DynamicPortForwarder : IAsyncDisposable
{
    private readonly SshConnection _connection;
    private readonly IPEndPoint _bindEndPoint;
    private readonly SshConnectionOptions _options;

    private Socket? _listener;
    private CancellationTokenSource? _cancellation;
    private Task _acceptLoop = Task.CompletedTask;
    private bool _disposed;

    /// <summary>
    /// Initializes the forwarder.
    /// </summary>
    /// <param name="connection">The authenticated connection to tunnel over.</param>
    /// <param name="bindEndPoint">The local endpoint to run the SOCKS proxy on (use port 0 for an ephemeral port).</param>
    /// <param name="options">Connection options for opened channels; defaults to the connection defaults.</param>
    /// <exception cref="ArgumentNullException">The connection or endpoint is null.</exception>
    public DynamicPortForwarder(SshConnection connection, IPEndPoint bindEndPoint, SshConnectionOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(bindEndPoint);
        _connection = connection;
        _bindEndPoint = bindEndPoint;
        _options = options ?? SshConnectionOptions.Default;
    }

    /// <summary>
    /// Gets the endpoint the SOCKS proxy is listening on, or null before <see cref="StartAsync"/>.
    /// </summary>
    public IPEndPoint? ListenEndPoint => _listener?.LocalEndPoint as IPEndPoint;

    /// <summary>
    /// Binds the SOCKS listener and starts accepting connections in the background.
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
            throw new SshForwardingException($"Failed to bind the dynamic forward endpoint {_bindEndPoint}: {exception.Message}", exception);
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
        SocksNegotiator negotiator = new SocksNegotiator();
        NetworkStream stream = new NetworkStream(socket, ownsSocket: false);
        SocksTarget target;
        try
        {
            target = await negotiator.NegotiateAsync(stream, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception)
        {
            await TryWriteFailureAndCloseAsync(negotiator, stream, socket, cancellationToken).ConfigureAwait(false);
            return;
        }

        SshChannel channel;
        try
        {
            IPEndPoint originator = (IPEndPoint)socket.RemoteEndPoint!;
            DirectTcpIpChannelRequest request = new DirectTcpIpChannelRequest(
                target.Host, target.Port, originator.Address.ToString(), originator.Port);
            channel = await _connection.OpenChannelAsync(request.ToChannelOpenParameters(_options), cancellationToken).ConfigureAwait(false);
        }
        catch (Exception)
        {
            await TryWriteFailureAndCloseAsync(negotiator, stream, socket, cancellationToken).ConfigureAwait(false);
            return;
        }

        try
        {
            await negotiator.WriteSuccessReplyAsync(stream, cancellationToken).ConfigureAwait(false);
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

    private static async Task TryWriteFailureAndCloseAsync(SocksNegotiator negotiator, NetworkStream stream, Socket socket, CancellationToken cancellationToken)
    {
        try
        {
            await negotiator.WriteFailureReplyAsync(stream, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // Best-effort — the client may already be gone or the version unknown.
        }
        try
        {
            socket.Dispose();
        }
        catch (Exception)
        {
            // Best-effort.
        }
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
