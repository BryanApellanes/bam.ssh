using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Bam.Ssh.Authentication;
using Bam.Ssh.Connection;
using Bam.Ssh.Transport;

namespace Bam.Ssh.Server;

/// <summary>
/// The high-level SSH server — the peer of <c>SshClient</c> that composes the whole
/// stack in server role: <see cref="SshTransport"/> (version exchange), <see cref="SshServerKeyExchange"/>
/// (key exchange, signing the exchange hash with an added host key), <see cref="SshServerAuthenticator"/>
/// (password and/or publickey policies), and <see cref="SshConnection"/> with an
/// <see cref="SshServerSession"/> handling <c>session</c> channels. Configure it — add a host key, choose
/// authentication, map <c>exec</c>/<c>shell</c>/<c>subsystem</c> handlers — then <see cref="StartAsync"/>
/// to listen on a TCP endpoint, or <see cref="AcceptAsync"/> to serve one already-established transport.
/// Configuration is frozen once serving begins. Disposing stops the listener and tears down every session.
/// </summary>
public sealed class SshServer : IAsyncDisposable
{
    private readonly SshServerOptions _options;
    private readonly ISshLogger _logger;
    private readonly List<ISshHostKeySigner> _hostKeys = new List<ISshHostKeySigner>();
    private readonly Dictionary<string, SshServerCommandHandler> _subsystems = new Dictionary<string, SshServerCommandHandler>(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<SshServerSession, byte> _sessions = new ConcurrentDictionary<SshServerSession, byte>();

    private ISshPasswordAuthenticator? _passwordAuthenticator;
    private ISshPublicKeyAuthenticator? _publicKeyAuthenticator;
    private SshServerCommandHandler? _execHandler;
    private SshServerCommandHandler? _shellHandler;

    private SshServerCommandMap? _commandMap;
    private Socket? _listener;
    private CancellationTokenSource? _shutdown;
    private SemaphoreSlim? _connectionLimit;
    private Task _acceptLoop = Task.CompletedTask;
    private volatile bool _serving;
    private bool _disposed;

    /// <summary>
    /// Initializes a server with the given options.
    /// </summary>
    /// <param name="options">Server options; defaults to <see cref="SshServerOptions"/> defaults.</param>
    /// <param name="logger">The logger; defaults to <see cref="NullSshLogger.Instance"/>.</param>
    public SshServer(SshServerOptions? options = null, ISshLogger? logger = null)
    {
        _options = options ?? new SshServerOptions();
        _logger = logger ?? NullSshLogger.Instance;
    }

    /// <summary>
    /// Gets the endpoint the server is listening on, or null before <see cref="StartAsync"/>.
    /// </summary>
    public IPEndPoint? ListenEndPoint => _listener?.LocalEndPoint as IPEndPoint;

    /// <summary>
    /// Adds a host key the server offers during key exchange. At least one is required. Adding several of
    /// different algorithms lets the server satisfy a wider range of clients; the one matching the
    /// negotiated host-key algorithm signs.
    /// </summary>
    /// <param name="hostKey">The host key (a Phase 5 private key doubles as a host-key signer).</param>
    /// <exception cref="ArgumentNullException">The host key is null.</exception>
    /// <exception cref="SshServerException">The server is already serving.</exception>
    public void AddHostKey(ISshHostKeySigner hostKey)
    {
        ArgumentNullException.ThrowIfNull(hostKey);
        EnsureNotServing();
        _hostKeys.Add(hostKey);
    }

    /// <summary>
    /// Enables password authentication with the given policy.
    /// </summary>
    /// <param name="authenticator">The policy that decides whether a user/password pair is valid.</param>
    /// <exception cref="ArgumentNullException">The authenticator is null.</exception>
    /// <exception cref="SshServerException">The server is already serving.</exception>
    public void UsePasswordAuthentication(ISshPasswordAuthenticator authenticator)
    {
        ArgumentNullException.ThrowIfNull(authenticator);
        EnsureNotServing();
        _passwordAuthenticator = authenticator;
    }

    /// <summary>
    /// Enables publickey authentication with the given policy.
    /// </summary>
    /// <param name="authenticator">The policy that decides whether a user's public key is authorized.</param>
    /// <exception cref="ArgumentNullException">The authenticator is null.</exception>
    /// <exception cref="SshServerException">The server is already serving.</exception>
    public void UsePublicKeyAuthentication(ISshPublicKeyAuthenticator authenticator)
    {
        ArgumentNullException.ThrowIfNull(authenticator);
        EnsureNotServing();
        _publicKeyAuthenticator = authenticator;
    }

    /// <summary>
    /// Maps the handler that serves <c>exec</c> requests (a single remote command line).
    /// </summary>
    /// <param name="handler">The handler.</param>
    /// <exception cref="ArgumentNullException">The handler is null.</exception>
    /// <exception cref="SshServerException">The server is already serving.</exception>
    public void MapExec(SshServerCommandHandler handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        EnsureNotServing();
        _execHandler = handler;
    }

    /// <summary>
    /// Maps the handler that serves <c>shell</c> requests (an interactive shell).
    /// </summary>
    /// <param name="handler">The handler.</param>
    /// <exception cref="ArgumentNullException">The handler is null.</exception>
    /// <exception cref="SshServerException">The server is already serving.</exception>
    public void MapShell(SshServerCommandHandler handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        EnsureNotServing();
        _shellHandler = handler;
    }

    /// <summary>
    /// Maps the handler that serves a named <c>subsystem</c> such as <c>sftp</c>.
    /// </summary>
    /// <param name="name">The subsystem name.</param>
    /// <param name="handler">The handler.</param>
    /// <exception cref="ArgumentException">The name is null or empty.</exception>
    /// <exception cref="ArgumentNullException">The handler is null.</exception>
    /// <exception cref="SshServerException">The server is already serving, or the name is already mapped.</exception>
    public void MapSubsystem(string name, SshServerCommandHandler handler)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        ArgumentNullException.ThrowIfNull(handler);
        EnsureNotServing();
        if (!_subsystems.TryAdd(name, handler))
        {
            throw new SshServerException($"A subsystem named '{name}' is already mapped.");
        }
    }

    /// <summary>
    /// Binds a TCP listener on the endpoint and begins accepting connections in the background. Pass port 0
    /// to bind an ephemeral port and read the chosen endpoint from <see cref="ListenEndPoint"/>.
    /// </summary>
    /// <param name="endPoint">The endpoint to listen on.</param>
    /// <param name="cancellationToken">Cancels binding (not the server lifetime; use <see cref="StopAsync"/>).</param>
    /// <exception cref="ArgumentNullException">The endpoint is null.</exception>
    /// <exception cref="SshServerException">The server is already serving, or no host key/authentication is configured.</exception>
    public ValueTask StartAsync(IPEndPoint endPoint, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(endPoint);
        ObjectDisposedException.ThrowIf(_disposed, this);
        cancellationToken.ThrowIfCancellationRequested();
        BeginServing();

        Socket listener = new Socket(endPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            listener.Bind(endPoint);
            listener.Listen(_options.Backlog);
        }
        catch (SocketException exception)
        {
            listener.Dispose();
            _serving = false;
            throw new SshServerException($"Failed to listen on {endPoint}: {exception.Message}", exception);
        }

        _listener = listener;
        _shutdown = new CancellationTokenSource();
        _connectionLimit = _options.MaxConcurrentConnections > 0
            ? new SemaphoreSlim(_options.MaxConcurrentConnections, _options.MaxConcurrentConnections)
            : null;
        _acceptLoop = AcceptLoopAsync(_shutdown.Token);
        if (_logger.IsEnabled(SshLogLevel.Information))
        {
            _logger.Log(SshLogLevel.Information, "SSH server listening on {0}.", _listener.LocalEndPoint!);
        }
        return ValueTask.CompletedTask;
    }

    /// <summary>
    /// Serves one peer over an already-established byte transport (a custom transport, a Unix socket, or a
    /// test loopback): version exchange, key exchange, authentication, then the channel connection. Returns
    /// the authenticated session once its connection is running. The caller owns the returned session and
    /// must dispose it. Used directly for embedding, and by the TCP accept loop.
    /// </summary>
    /// <param name="stream">The connected byte transport. Owned by the returned session.</param>
    /// <param name="cancellationToken">Cancels the handshake and bounds the served connection's lifetime.</param>
    /// <returns>The authenticated, running session.</returns>
    /// <exception cref="ArgumentNullException">The stream is null.</exception>
    /// <exception cref="SshServerException">No host key or authentication method is configured.</exception>
    public async ValueTask<SshServerSession> AcceptAsync(ISshDuplexStream stream, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_hostKeys.Count == 0)
        {
            throw new SshServerException("At least one host key must be added before accepting connections.");
        }
        if (_passwordAuthenticator == null && _publicKeyAuthenticator == null)
        {
            throw new SshServerException("At least one authentication method must be configured before accepting connections.");
        }

        SshServerCommandMap commandMap = EnsureCommandMap();
        IReadOnlyList<ISshHostKeySigner> hostKeys = _hostKeys.ToArray();

        SshTransport transport = new SshTransport(stream, _options.ToTransportOptions(), _logger);
        try
        {
            await transport.ConnectAsync(cancellationToken).ConfigureAwait(false);

            SshServerKeyExchange keyExchange = new SshServerKeyExchange(transport, hostKeys, logger: _logger);
            SshKeyExchangeResult kexResult = await keyExchange.PerformAsync(cancellationToken).ConfigureAwait(false);
            byte[] sessionId = kexResult.SessionKeys.SessionId;

            SshServerAuthenticator authenticator = new SshServerAuthenticator(
                transport, sessionId, _passwordAuthenticator, _publicKeyAuthenticator, _options.Banner, _logger);
            SshServerAuthenticationResult authResult = await authenticator.AuthenticateAsync(cancellationToken).ConfigureAwait(false);

            SshServerSession session = new SshServerSession(authResult.UserName, commandMap, cancellationToken, _logger);
            SshConnection connection = new SshConnection(
                transport, sessionId, keyExchange, _options.ConnectionOptions, _logger, session);
            session.AttachConnection(connection);
            if (_logger.IsEnabled(SshLogLevel.Information))
            {
                _logger.Log(SshLogLevel.Information, "Authenticated user '{0}' via {1}.", authResult.UserName, authResult.MethodUsed);
            }
            return session;
        }
        catch
        {
            await transport.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>
    /// Stops accepting new connections and tears down every active session.
    /// </summary>
    /// <param name="cancellationToken">Cancels waiting for the accept loop to drain.</param>
    public async ValueTask StopAsync(CancellationToken cancellationToken = default)
    {
        if (!_serving)
        {
            return;
        }
        _serving = false;
        _shutdown?.Cancel();
        _listener?.Dispose();
        try
        {
            await _acceptLoop.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Best-effort drain.
        }

        foreach (SshServerSession session in _sessions.Keys)
        {
            _sessions.TryRemove(session, out _);
            await session.DisposeAsync().ConfigureAwait(false);
        }
    }

    private async Task AcceptLoopAsync(CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                if (_connectionLimit != null)
                {
                    await _connectionLimit.WaitAsync(cancellationToken).ConfigureAwait(false);
                }

                Socket socket;
                try
                {
                    socket = await _listener!.AcceptAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    _connectionLimit?.Release();
                    break;
                }
                catch (ObjectDisposedException)
                {
                    _connectionLimit?.Release();
                    break;
                }
                _ = HandleAcceptedSocketAsync(socket, cancellationToken);
            }
        }
        catch (OperationCanceledException)
        {
            // Shutdown.
        }
    }

    private async Task HandleAcceptedSocketAsync(Socket socket, CancellationToken cancellationToken)
    {
        SshServerSession? session = null;
        try
        {
            SshTcpDuplexStream stream = SshTcpDuplexStream.FromConnectedSocket(socket);
            session = await AcceptAsync(stream, cancellationToken).ConfigureAwait(false);
            _sessions.TryAdd(session, 0);
            await session.Connection.Completion.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Shutdown or handshake cancelled.
        }
        catch (Exception exception)
        {
            if (_logger.IsEnabled(SshLogLevel.Warning))
            {
                _logger.Log(SshLogLevel.Warning, "Serving a peer connection failed: {0}", exception.Message);
            }
        }
        finally
        {
            if (session != null)
            {
                _sessions.TryRemove(session, out _);
                await session.DisposeAsync().ConfigureAwait(false);
            }
            else
            {
                try
                {
                    socket.Dispose();
                }
                catch (Exception)
                {
                    // Best-effort.
                }
            }
            _connectionLimit?.Release();
        }
    }

    private SshServerCommandMap EnsureCommandMap()
    {
        return _commandMap ??= new SshServerCommandMap(
            _execHandler,
            _shellHandler,
            new Dictionary<string, SshServerCommandHandler>(_subsystems, StringComparer.Ordinal));
    }

    private void BeginServing()
    {
        EnsureNotServing();
        if (_hostKeys.Count == 0)
        {
            throw new SshServerException("At least one host key must be added before starting the server.");
        }
        if (_passwordAuthenticator == null && _publicKeyAuthenticator == null)
        {
            throw new SshServerException("At least one authentication method must be configured before starting the server.");
        }
        EnsureCommandMap();
        _serving = true;
    }

    private void EnsureNotServing()
    {
        if (_serving)
        {
            throw new SshServerException("The server is already serving; configuration is frozen.");
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
        await StopAsync(CancellationToken.None).ConfigureAwait(false);
        _shutdown?.Dispose();
        _connectionLimit?.Dispose();
    }
}
