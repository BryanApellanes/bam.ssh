using Bam.Ssh.Connection;

namespace Bam.Ssh.Forwarding;

/// <summary>
/// Remote (<c>-R</c>) port forwarding from the client side: sends a <c>tcpip-forward</c> global request
/// asking the server to listen on a port, then services the <c>forwarded-tcpip</c> channels the server opens
/// when connections arrive there by connecting to a fixed local target and bridging. Disposing cancels the
/// forward (<c>cancel-tcpip-forward</c>) and stops routing.
/// </summary>
public sealed class RemotePortForwarder : IAsyncDisposable
{
    private readonly SshConnection _connection;
    private readonly string _bindAddress;
    private readonly int _requestedBindPort;
    private readonly string _localHost;
    private readonly int _localPort;
    private readonly SshConnectionOptions _options;

    private ForwardedTcpIpChannelAcceptor? _acceptor;
    private int _boundPort;
    private bool _started;
    private bool _disposed;

    /// <summary>
    /// Initializes the forwarder.
    /// </summary>
    /// <param name="connection">The authenticated connection to tunnel over.</param>
    /// <param name="bindAddress">The address the server should bind (empty or <c>0.0.0.0</c> for all interfaces).</param>
    /// <param name="bindPort">The port the server should bind (0 to let the server choose).</param>
    /// <param name="localHost">The local host to connect forwarded connections to.</param>
    /// <param name="localPort">The local port to connect forwarded connections to.</param>
    /// <param name="options">Connection options for opened channels; defaults to the connection defaults.</param>
    /// <exception cref="ArgumentNullException">The connection, bind address, or local host is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">A port is outside 0–65535.</exception>
    public RemotePortForwarder(SshConnection connection, string bindAddress, int bindPort, string localHost, int localPort, SshConnectionOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(bindAddress);
        ArgumentException.ThrowIfNullOrEmpty(localHost);
        ForwardingPort.Validate(bindPort);
        ForwardingPort.Validate(localPort);
        _connection = connection;
        _bindAddress = bindAddress;
        _requestedBindPort = bindPort;
        _localHost = localHost;
        _localPort = localPort;
        _options = options ?? SshConnectionOptions.Default;
    }

    /// <summary>
    /// Gets the port the server actually bound (valid after <see cref="StartAsync"/>).
    /// </summary>
    public int BoundPort => _boundPort;

    /// <summary>
    /// Requests the forward from the server and begins routing forwarded connections to the local target.
    /// </summary>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The port the server bound (the requested port, or the server-chosen port when 0 was requested).</returns>
    /// <exception cref="SshForwardingException">The server refused the forward.</exception>
    public async ValueTask<int> StartAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        TcpIpForwardRequest request = new TcpIpForwardRequest(_bindAddress, _requestedBindPort);
        SshGlobalRequestReply reply = await _connection.SendGlobalRequestWithReplyAsync(
            SshForwardingNames.TcpIpForward, request.ToRequestData(), cancellationToken).ConfigureAwait(false);
        if (!reply.Success)
        {
            throw new SshForwardingException($"The server refused to forward {_bindAddress}:{_requestedBindPort}.");
        }

        _boundPort = _requestedBindPort != 0
            ? _requestedBindPort
            : TcpIpForwardRequest.ParseBoundPortReply(reply.Data.Span);
        _acceptor = ForwardedTcpIpChannelAcceptor.GetOrCreate(_connection);
        _acceptor.AddBinding(_boundPort, _localHost, _localPort, _options);
        _started = true;
        return _boundPort;
    }

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        if (!_started)
        {
            return;
        }

        _acceptor?.RemoveBinding(_boundPort);
        try
        {
            TcpIpForwardRequest cancel = new TcpIpForwardRequest(_bindAddress, _boundPort);
            await _connection.SendGlobalRequestAsync(
                SshForwardingNames.CancelTcpIpForward, wantReply: false, cancel.ToRequestData(), CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // The connection may already be gone; cancellation is best-effort.
        }
    }
}
