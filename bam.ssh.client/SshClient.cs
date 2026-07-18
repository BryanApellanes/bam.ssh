using System.Net;
using Bam.Ssh.Authentication;
using Bam.Ssh.Connection;
using Bam.Ssh.Forwarding;
using Bam.Ssh.Transport;

namespace Bam.Ssh.Client;

/// <summary>
/// The high-level SSH client — an <c>HttpClient</c>-shaped façade that composes the whole stack:
/// <see cref="SshTransport"/> (version exchange), <see cref="SshClientKeyExchange"/> (key exchange),
/// host-key trust (<see cref="ISshHostKeyVerifier"/>), <see cref="SshUserAuthenticator"/>
/// (authentication), and <see cref="SshConnection"/> (multiplexed channels). Typical use: <c>ConnectAsync</c>,
/// then an <c>Authenticate…</c> call, then <c>ExecuteAsync</c> / <c>OpenShellAsync</c>. The host key is
/// verified after key exchange and before any credentials are sent. Not thread-safe for connect/authenticate;
/// once authenticated, channels may be opened concurrently. Disposing tears down the connection and transport.
/// </summary>
public sealed class SshClient : IAsyncDisposable
{
    private readonly SshClientOptions _options;
    private readonly ISshLogger _logger;

    private SshTransport? _transport;
    private SshClientKeyExchange? _keyExchange;
    private SshConnection? _connection;
    private SshClientKeepAlive? _keepAlive;
    private byte[]? _sessionId;
    private string _host = string.Empty;
    private int _port;
    private SshClientState _state = SshClientState.Created;
    private bool _disposed;

    /// <summary>
    /// Initializes a client with the given options.
    /// </summary>
    /// <param name="options">Client options; defaults to <see cref="SshClientOptions"/> defaults.</param>
    /// <param name="logger">The logger; defaults to <see cref="NullSshLogger.Instance"/>.</param>
    public SshClient(SshClientOptions? options = null, ISshLogger? logger = null)
    {
        _options = options ?? new SshClientOptions();
        _logger = logger ?? NullSshLogger.Instance;
    }

    /// <summary>
    /// Gets the connection once authenticated (for advanced channel/global-request use).
    /// </summary>
    /// <exception cref="SshConnectionStateException">The client is not authenticated.</exception>
    public SshConnection Connection => _connection ?? throw new SshConnectionStateException("The client is not authenticated.");

    /// <summary>
    /// Connects to a host over TCP and completes version exchange, key exchange, and host-key verification.
    /// </summary>
    /// <param name="host">The host name or address.</param>
    /// <param name="port">The port; defaults to 22.</param>
    /// <param name="cancellationToken">Cancels the connect.</param>
    /// <exception cref="ArgumentException">The host is null or empty.</exception>
    /// <exception cref="SshHostKeyRejectedException">The host key was not trusted.</exception>
    public async ValueTask ConnectAsync(string host, int port = 22, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(host);
        SshTcpDuplexStream stream = await SshTcpDuplexStream.ConnectAsync(host, port, cancellationToken).ConfigureAwait(false);
        await ConnectAsync(stream, host, port, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Connects over an already-established byte transport (a custom transport, a Unix socket, or a test
    /// loopback), then completes version exchange, key exchange, and host-key verification.
    /// </summary>
    /// <param name="stream">The connected byte transport. Owned by the client.</param>
    /// <param name="host">The host name (for known_hosts matching and diagnostics).</param>
    /// <param name="port">The port (for known_hosts matching and diagnostics).</param>
    /// <param name="cancellationToken">Cancels the connect.</param>
    /// <exception cref="ArgumentNullException">The stream is null.</exception>
    /// <exception cref="ArgumentException">The host is null or empty.</exception>
    /// <exception cref="SshConnectionStateException">The client is already connected.</exception>
    /// <exception cref="SshHostKeyRejectedException">The host key was not trusted.</exception>
    public async ValueTask ConnectAsync(ISshDuplexStream stream, string host, int port, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentException.ThrowIfNullOrEmpty(host);
        EnsureState(SshClientState.Created, "connect");

        SshTransport transport = new SshTransport(stream, _options.ToTransportOptions(), _logger);
        await transport.ConnectAsync(cancellationToken).ConfigureAwait(false);

        SshClientKeyExchange keyExchange = new SshClientKeyExchange(transport, logger: _logger);
        SshKeyExchangeResult result = await keyExchange.PerformAsync(cancellationToken).ConfigureAwait(false);

        SshHostKeyVerificationContext context = new SshHostKeyVerificationContext(host, port, result.HostKey);
        bool trusted = await _options.HostKeyVerifier.VerifyAsync(context, cancellationToken).ConfigureAwait(false);
        if (!trusted)
        {
            await transport.SendDisconnectAsync(SshDisconnectReason.HostKeyNotVerifiable, "Host key not trusted.", cancellationToken).ConfigureAwait(false);
            await transport.DisposeAsync().ConfigureAwait(false);
            throw new SshHostKeyRejectedException(host, result.HostKey.Fingerprint);
        }

        _transport = transport;
        _keyExchange = keyExchange;
        _sessionId = result.SessionKeys.SessionId;
        _host = host;
        _port = port;
        _state = SshClientState.Connected;
    }

    /// <summary>
    /// Authenticates the user by trying the given methods in order (Phase 5 <see cref="ISshAuthenticationMethod"/>s).
    /// </summary>
    /// <param name="userName">The user name.</param>
    /// <param name="methods">The methods to try, in preference order.</param>
    /// <param name="cancellationToken">Cancels the authentication.</param>
    /// <exception cref="ArgumentException">The user name is null or empty.</exception>
    /// <exception cref="ArgumentNullException">The methods list is null.</exception>
    /// <exception cref="SshConnectionStateException">The client is not connected.</exception>
    /// <exception cref="SshAuthenticationException">Every method failed.</exception>
    public async ValueTask AuthenticateAsync(string userName, IReadOnlyList<ISshAuthenticationMethod> methods, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(userName);
        ArgumentNullException.ThrowIfNull(methods);
        EnsureState(SshClientState.Connected, "authenticate");

        SshUserAuthenticator authenticator = new SshUserAuthenticator(_transport!, _sessionId!, logger: _logger);
        SshAuthenticationResult result = await authenticator.AuthenticateAsync(userName, methods, cancellationToken).ConfigureAwait(false);
        if (!result.Succeeded)
        {
            string continued = string.Join(", ", result.MethodsThatCanContinue);
            throw new SshAuthenticationException($"Authentication failed for user '{userName}'. Methods that can continue: {continued}.");
        }

        _connection = new SshConnection(_transport!, _sessionId!, _keyExchange, _options.ConnectionOptions, _logger);
        if (_options.KeepAliveInterval is TimeSpan interval)
        {
            _keepAlive = new SshClientKeepAlive(_connection, interval, _logger);
            _keepAlive.Start();
        }
        _state = SshClientState.Authenticated;
    }

    /// <summary>
    /// Authenticates with a password.
    /// </summary>
    /// <param name="userName">The user name.</param>
    /// <param name="password">The password.</param>
    /// <param name="cancellationToken">Cancels the authentication.</param>
    public ValueTask AuthenticateWithPasswordAsync(string userName, string password, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(password);
        return AuthenticateAsync(userName, new ISshAuthenticationMethod[] { new PasswordAuthenticationMethod(password) }, cancellationToken);
    }

    /// <summary>
    /// Authenticates with a public key.
    /// </summary>
    /// <param name="userName">The user name.</param>
    /// <param name="privateKey">The private key to authenticate with.</param>
    /// <param name="cancellationToken">Cancels the authentication.</param>
    public ValueTask AuthenticateWithPublicKeyAsync(string userName, ISshPrivateKey privateKey, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        return AuthenticateAsync(userName, new ISshAuthenticationMethod[] { new PublicKeyAuthenticationMethod(privateKey) }, cancellationToken);
    }

    /// <summary>
    /// Runs a command on the remote host and returns its exit code and captured output.
    /// </summary>
    /// <param name="command">The command line to execute.</param>
    /// <param name="cancellationToken">Cancels the command.</param>
    /// <returns>The command result.</returns>
    /// <exception cref="ArgumentNullException">The command is null.</exception>
    /// <exception cref="SshConnectionStateException">The client is not authenticated, or the server refused the command.</exception>
    public async ValueTask<SshCommandResult> ExecuteAsync(string command, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);
        SshConnection connection = EnsureAuthenticated();

        SshSessionChannel channel = await connection.OpenSessionChannelAsync(cancellationToken).ConfigureAwait(false);
        int? exitCode = null;
        channel.ExitStatusReceived += (sender, e) => exitCode = unchecked((int)e.ExitCode);

        if (!await channel.ExecAsync(command, cancellationToken).ConfigureAwait(false))
        {
            await channel.Channel.CloseAsync(cancellationToken).ConfigureAwait(false);
            throw new SshConnectionStateException($"The server refused to execute the command '{command}'.");
        }

        Task<byte[]> standardOutput = ReadStreamAsync(channel.Channel.ReadAsync, cancellationToken);
        Task<byte[]> standardError = ReadStreamAsync(channel.Channel.ReadExtendedAsync, cancellationToken);
        await Task.WhenAll(standardOutput, standardError).ConfigureAwait(false);
        await channel.Channel.CloseAsync(cancellationToken).ConfigureAwait(false);

        return new SshCommandResult(exitCode, standardOutput.Result, standardError.Result);
    }

    /// <summary>
    /// Opens a bare session channel for advanced use (custom requests, streaming I/O).
    /// </summary>
    /// <param name="cancellationToken">Cancels the open.</param>
    /// <returns>The opened session channel.</returns>
    /// <exception cref="SshConnectionStateException">The client is not authenticated.</exception>
    public ValueTask<SshSessionChannel> OpenSessionChannelAsync(CancellationToken cancellationToken = default)
    {
        return EnsureAuthenticated().OpenSessionChannelAsync(cancellationToken);
    }

    /// <summary>
    /// Opens an interactive shell, optionally allocating a pseudo-terminal first.
    /// </summary>
    /// <param name="pseudoTerminal">The pseudo-terminal to request, or null for no PTY.</param>
    /// <param name="cancellationToken">Cancels the open.</param>
    /// <returns>The session channel running the shell.</returns>
    /// <exception cref="SshConnectionStateException">The client is not authenticated, or the server refused the shell.</exception>
    public async ValueTask<SshSessionChannel> OpenShellAsync(SshPseudoTerminalParameters? pseudoTerminal = null, CancellationToken cancellationToken = default)
    {
        SshConnection connection = EnsureAuthenticated();
        SshSessionChannel channel = await connection.OpenSessionChannelAsync(cancellationToken).ConfigureAwait(false);
        if (pseudoTerminal != null)
        {
            await channel.RequestPseudoTerminalAsync(pseudoTerminal, cancellationToken).ConfigureAwait(false);
        }
        if (!await channel.ShellAsync(cancellationToken).ConfigureAwait(false))
        {
            await channel.Channel.CloseAsync(cancellationToken).ConfigureAwait(false);
            throw new SshConnectionStateException("The server refused to start a shell.");
        }
        return channel;
    }

    /// <summary>
    /// Starts local (<c>-L</c>) forwarding: listens on a local port and tunnels each connection to a remote
    /// target reachable from the server. Dispose the returned forwarder to stop listening.
    /// </summary>
    /// <param name="localPort">The local port to listen on (0 for an ephemeral port; read it from the result's ListenEndPoint).</param>
    /// <param name="remoteHost">The host the server connects to.</param>
    /// <param name="remotePort">The port the server connects to.</param>
    /// <param name="localBindAddress">The local address to bind; defaults to loopback.</param>
    /// <param name="cancellationToken">Cancels the bind.</param>
    /// <returns>The running forwarder.</returns>
    /// <exception cref="SshConnectionStateException">The client is not authenticated.</exception>
    public async ValueTask<LocalPortForwarder> ForwardLocalPortAsync(int localPort, string remoteHost, int remotePort, string localBindAddress = "127.0.0.1", CancellationToken cancellationToken = default)
    {
        SshConnection connection = EnsureAuthenticated();
        IPEndPoint bindEndPoint = new IPEndPoint(IPAddress.Parse(localBindAddress), localPort);
        LocalPortForwarder forwarder = new LocalPortForwarder(connection, bindEndPoint, remoteHost, remotePort, _options.ConnectionOptions);
        await forwarder.StartAsync(cancellationToken).ConfigureAwait(false);
        return forwarder;
    }

    /// <summary>
    /// Starts dynamic (<c>-D</c>) forwarding: runs a local SOCKS proxy and tunnels each negotiated connection
    /// through the server. Dispose the returned forwarder to stop listening.
    /// </summary>
    /// <param name="localPort">The local port to run the SOCKS proxy on (0 for an ephemeral port).</param>
    /// <param name="localBindAddress">The local address to bind; defaults to loopback.</param>
    /// <param name="cancellationToken">Cancels the bind.</param>
    /// <returns>The running forwarder.</returns>
    /// <exception cref="SshConnectionStateException">The client is not authenticated.</exception>
    public async ValueTask<DynamicPortForwarder> ForwardDynamicPortAsync(int localPort, string localBindAddress = "127.0.0.1", CancellationToken cancellationToken = default)
    {
        SshConnection connection = EnsureAuthenticated();
        IPEndPoint bindEndPoint = new IPEndPoint(IPAddress.Parse(localBindAddress), localPort);
        DynamicPortForwarder forwarder = new DynamicPortForwarder(connection, bindEndPoint, _options.ConnectionOptions);
        await forwarder.StartAsync(cancellationToken).ConfigureAwait(false);
        return forwarder;
    }

    /// <summary>
    /// Starts remote (<c>-R</c>) forwarding: asks the server to listen on a port and tunnels each connection
    /// there to a local target. Dispose the returned forwarder to cancel the forward.
    /// </summary>
    /// <param name="remotePort">The port the server binds (0 to let the server choose; read the chosen port from the result's BoundPort).</param>
    /// <param name="localHost">The local host forwarded connections are routed to.</param>
    /// <param name="localPort">The local port forwarded connections are routed to.</param>
    /// <param name="remoteBindAddress">The address the server binds; empty (default) for all interfaces.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The running forwarder (its BoundPort holds the server-bound port).</returns>
    /// <exception cref="SshConnectionStateException">The client is not authenticated.</exception>
    /// <exception cref="SshForwardingException">The server refused the forward.</exception>
    public async ValueTask<RemotePortForwarder> ForwardRemotePortAsync(int remotePort, string localHost, int localPort, string remoteBindAddress = "", CancellationToken cancellationToken = default)
    {
        SshConnection connection = EnsureAuthenticated();
        RemotePortForwarder forwarder = new RemotePortForwarder(connection, remoteBindAddress, remotePort, localHost, localPort, _options.ConnectionOptions);
        await forwarder.StartAsync(cancellationToken).ConfigureAwait(false);
        return forwarder;
    }

    private static async Task<byte[]> ReadStreamAsync(Func<Memory<byte>, CancellationToken, ValueTask<int>> read, CancellationToken cancellationToken)
    {
        using MemoryStream buffer = new MemoryStream();
        byte[] rented = new byte[8192];
        while (true)
        {
            int count = await read(rented, cancellationToken).ConfigureAwait(false);
            if (count == 0)
            {
                return buffer.ToArray();
            }
            buffer.Write(rented, 0, count);
        }
    }

    private SshConnection EnsureAuthenticated()
    {
        if (_state != SshClientState.Authenticated || _connection == null)
        {
            throw new SshConnectionStateException("The client must be authenticated before running commands or opening channels.");
        }
        return _connection;
    }

    private void EnsureState(SshClientState expected, string operation)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_state != expected)
        {
            throw new SshConnectionStateException($"Cannot {operation}: the client is in state {_state}, expected {expected}.");
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
        _state = SshClientState.Disposed;
        if (_keepAlive != null)
        {
            await _keepAlive.DisposeAsync().ConfigureAwait(false);
        }
        if (_connection != null)
        {
            await _connection.DisposeAsync().ConfigureAwait(false);
        }
        else if (_transport != null)
        {
            await _transport.DisposeAsync().ConfigureAwait(false);
        }
    }

    private enum SshClientState
    {
        Created,
        Connected,
        Authenticated,
        Disposed,
    }
}
