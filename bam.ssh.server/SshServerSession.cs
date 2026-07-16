using Bam.Ssh.Connection;
using Bam.Ssh.Transport;

namespace Bam.Ssh.Server;

/// <summary>
/// The server side of one authenticated peer connection: it is the connection's
/// <see cref="ISshChannelOpenHandler"/>, accepting <c>session</c> channels and translating each channel's
/// <c>pty-req</c>/<c>env</c>/<c>exec</c>/<c>shell</c>/<c>subsystem</c> requests into a mapped
/// <see cref="SshServerCommandHandler"/> run off the receive-dispatch loop. Non-session opens and unmapped
/// commands are refused. Disposing tears down the underlying <see cref="SshConnection"/>.
/// </summary>
public sealed class SshServerSession : ISshChannelOpenHandler, IAsyncDisposable
{
    private const string SessionChannelType = "session";
    private const string PseudoTerminalRequest = "pty-req";
    private const string EnvironmentRequest = "env";
    private const string ShellRequest = "shell";
    private const string ExecRequest = "exec";
    private const string SubsystemRequest = "subsystem";
    private const string WindowChangeRequest = "window-change";
    private const string SignalRequest = "signal";

    private readonly SshServerCommandMap _commandMap;
    private readonly CancellationToken _shutdownToken;
    private readonly ISshLogger _logger;

    private SshConnection? _connection;

    internal SshServerSession(string userName, SshServerCommandMap commandMap, CancellationToken shutdownToken, ISshLogger logger)
    {
        UserName = userName;
        _commandMap = commandMap;
        _shutdownToken = shutdownToken;
        _logger = logger;
    }

    /// <summary>
    /// Gets the authenticated user this session serves.
    /// </summary>
    public string UserName { get; }

    /// <summary>
    /// Gets the multiplexed connection once attached (for advanced channel/global-request use).
    /// </summary>
    /// <exception cref="SshServerException">The connection has not been attached yet.</exception>
    public SshConnection Connection => _connection ?? throw new SshServerException("The session connection is not attached.");

    internal void AttachConnection(SshConnection connection)
    {
        _connection = connection;
    }

    /// <inheritdoc/>
    public ValueTask HandleOpenAsync(SshChannelOpenRequestContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (!string.Equals(context.ChannelType, SessionChannelType, StringComparison.Ordinal))
        {
            // Leave unresolved: the connection refuses the open with UnknownChannelType.
            return ValueTask.CompletedTask;
        }

        SshChannel channel = context.Accept();
        ChannelState state = new ChannelState();
        channel.RequestReceived += (sender, request) => OnRequestReceived(channel, state, request);
        return ValueTask.CompletedTask;
    }

    private void OnRequestReceived(SshChannel channel, ChannelState state, SshChannelRequestEventArgs request)
    {
        switch (request.RequestType)
        {
            case PseudoTerminalRequest:
                state.PseudoTerminalRequested = true;
                request.Reply(true);
                break;
            case EnvironmentRequest:
            case WindowChangeRequest:
            case SignalRequest:
                request.Reply(true);
                break;
            case ExecRequest:
                StartCommand(channel, state, request, SshServerCommandType.Exec, ReadText(request.RequestData.Span), string.Empty);
                break;
            case ShellRequest:
                StartCommand(channel, state, request, SshServerCommandType.Shell, string.Empty, string.Empty);
                break;
            case SubsystemRequest:
                StartCommand(channel, state, request, SshServerCommandType.Subsystem, string.Empty, ReadText(request.RequestData.Span));
                break;
            default:
                request.Reply(false);
                break;
        }
    }

    private void StartCommand(
        SshChannel channel,
        ChannelState state,
        SshChannelRequestEventArgs request,
        SshServerCommandType commandType,
        string commandLine,
        string subsystemName)
    {
        string argument = commandType == SshServerCommandType.Subsystem ? subsystemName : commandLine;
        SshServerCommandHandler? handler = _commandMap.Resolve(commandType, argument);
        if (state.Started || handler == null)
        {
            request.Reply(false);
            return;
        }

        state.Started = true;
        request.Reply(true);
        SshServerCommandContext commandContext = new SshServerCommandContext(channel, UserName, commandType, commandLine, subsystemName);
        _ = Task.Run(() => RunHandlerAsync(commandContext, handler), _shutdownToken);
    }

    private async Task RunHandlerAsync(SshServerCommandContext context, SshServerCommandHandler handler)
    {
        try
        {
            await handler(context, _shutdownToken).ConfigureAwait(false);
            await context.CompleteAsync(0, _shutdownToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Server shutdown or connection teardown; the channel is faulted elsewhere.
        }
        catch (Exception exception)
        {
            if (_logger.IsEnabled(SshLogLevel.Warning))
            {
                _logger.Log(SshLogLevel.Warning, "Command handler for user '{0}' failed: {1}", UserName, exception.Message);
            }
            try
            {
                await context.CompleteAsync(1, CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception)
            {
                // Best-effort finalization; the connection may already be gone.
            }
        }
    }

    private static string ReadText(ReadOnlySpan<byte> data)
    {
        try
        {
            SshWireReader reader = new SshWireReader(data);
            return reader.ReadText();
        }
        catch (SshWireFormatException)
        {
            return string.Empty;
        }
    }

    /// <inheritdoc/>
    public ValueTask DisposeAsync()
    {
        return _connection?.DisposeAsync() ?? ValueTask.CompletedTask;
    }

    private sealed class ChannelState
    {
        public bool Started { get; set; }

        public bool PseudoTerminalRequested { get; set; }
    }
}
