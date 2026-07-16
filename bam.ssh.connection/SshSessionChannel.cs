using Bam.Ssh.Transport;

namespace Bam.Ssh.Connection;

/// <summary>
/// A <c>session</c> channel (RFC 4254 §6): composes a generic <see cref="SshChannel"/> and adds the
/// session-type requests — <c>pty-req</c>, <c>env</c>, <c>shell</c>, <c>exec</c>, <c>subsystem</c>,
/// <c>signal</c>, and <c>window-change</c> — and translates the peer's inbound <c>exit-status</c> and
/// <c>exit-signal</c> requests into events. Data I/O is delegated to the composed channel.
/// </summary>
public sealed class SshSessionChannel
{
    private const string PseudoTerminalRequest = "pty-req";
    private const string EnvironmentRequest = "env";
    private const string ShellRequest = "shell";
    private const string ExecRequest = "exec";
    private const string SubsystemRequest = "subsystem";
    private const string SignalRequest = "signal";
    private const string WindowChangeRequest = "window-change";
    private const string ExitStatusRequest = "exit-status";
    private const string ExitSignalRequest = "exit-signal";

    private readonly SshChannel _channel;

    /// <summary>
    /// Wraps an already-open generic channel with session semantics and begins translating inbound
    /// session requests.
    /// </summary>
    /// <param name="channel">The open channel to compose.</param>
    /// <exception cref="ArgumentNullException">The channel is null.</exception>
    public SshSessionChannel(SshChannel channel)
    {
        ArgumentNullException.ThrowIfNull(channel);
        _channel = channel;
        _channel.RequestReceived += OnRequestReceived;
    }

    /// <summary>
    /// Raised when the peer reports the remote command's exit code via <c>exit-status</c>.
    /// </summary>
    public event EventHandler<SshChannelExitStatusEventArgs>? ExitStatusReceived;

    /// <summary>
    /// Raised when the peer reports that the remote command was killed by a signal via <c>exit-signal</c>.
    /// </summary>
    public event EventHandler<SshChannelExitSignalEventArgs>? ExitSignalReceived;

    /// <summary>
    /// Gets the composed generic channel.
    /// </summary>
    public SshChannel Channel => _channel;

    /// <summary>
    /// Requests a pseudo-terminal for the session (RFC 4254 §6.2).
    /// </summary>
    /// <param name="parameters">The terminal parameters.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>True if the server granted the pseudo-terminal.</returns>
    /// <exception cref="ArgumentNullException">The parameters are null.</exception>
    public ValueTask<bool> RequestPseudoTerminalAsync(SshPseudoTerminalParameters parameters, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        byte[] payload = BuildPayload((ref SshWireWriter writer) =>
        {
            writer.WriteText(parameters.TerminalType);
            writer.WriteUInt32(parameters.Columns);
            writer.WriteUInt32(parameters.Rows);
            writer.WriteUInt32(parameters.WidthPixels);
            writer.WriteUInt32(parameters.HeightPixels);
            writer.WriteString(parameters.EncodedModes.Span);
        });
        return _channel.SendRequestAsync(PseudoTerminalRequest, wantReply: true, payload, cancellationToken);
    }

    /// <summary>
    /// Sets an environment variable for the session (RFC 4254 §6.4). Servers commonly ignore this
    /// unless the variable is allow-listed, so no reply is requested.
    /// </summary>
    /// <param name="name">The variable name.</param>
    /// <param name="value">The variable value.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <exception cref="ArgumentNullException">The name or value is null.</exception>
    public async ValueTask SetEnvironmentAsync(string name, string value, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(value);
        byte[] payload = BuildPayload((ref SshWireWriter writer) =>
        {
            writer.WriteText(name);
            writer.WriteText(value);
        });
        await _channel.SendRequestAsync(EnvironmentRequest, wantReply: false, payload, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Starts the user's default interactive shell (RFC 4254 §6.5).
    /// </summary>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>True if the server started the shell.</returns>
    public ValueTask<bool> ShellAsync(CancellationToken cancellationToken = default)
    {
        return _channel.SendRequestAsync(ShellRequest, wantReply: true, ReadOnlyMemory<byte>.Empty, cancellationToken);
    }

    /// <summary>
    /// Runs a single command on the remote host (RFC 4254 §6.5).
    /// </summary>
    /// <param name="command">The command line to execute.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>True if the server accepted the command.</returns>
    /// <exception cref="ArgumentNullException">The command is null.</exception>
    public ValueTask<bool> ExecAsync(string command, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);
        byte[] payload = BuildPayload((ref SshWireWriter writer) => writer.WriteText(command));
        return _channel.SendRequestAsync(ExecRequest, wantReply: true, payload, cancellationToken);
    }

    /// <summary>
    /// Starts a named subsystem such as <c>sftp</c> (RFC 4254 §6.5).
    /// </summary>
    /// <param name="name">The subsystem name.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>True if the server started the subsystem.</returns>
    /// <exception cref="ArgumentNullException">The name is null.</exception>
    public ValueTask<bool> SubsystemAsync(string name, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(name);
        byte[] payload = BuildPayload((ref SshWireWriter writer) => writer.WriteText(name));
        return _channel.SendRequestAsync(SubsystemRequest, wantReply: true, payload, cancellationToken);
    }

    /// <summary>
    /// Delivers a signal to the remote process (RFC 4254 §6.9). No reply is requested.
    /// </summary>
    /// <param name="signalName">The signal name without the SIG prefix (e.g. <c>INT</c>).</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <exception cref="ArgumentNullException">The signal name is null.</exception>
    public async ValueTask SendSignalAsync(string signalName, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signalName);
        byte[] payload = BuildPayload((ref SshWireWriter writer) => writer.WriteText(signalName));
        await _channel.SendRequestAsync(SignalRequest, wantReply: false, payload, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Notifies the server that the terminal dimensions changed (RFC 4254 §6.7). No reply is requested.
    /// </summary>
    /// <param name="columns">The new width in characters.</param>
    /// <param name="rows">The new height in rows.</param>
    /// <param name="widthPixels">The new width in pixels (0 when unknown).</param>
    /// <param name="heightPixels">The new height in pixels (0 when unknown).</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    public async ValueTask SendWindowChangeAsync(uint columns, uint rows, uint widthPixels = 0, uint heightPixels = 0, CancellationToken cancellationToken = default)
    {
        byte[] payload = BuildPayload((ref SshWireWriter writer) =>
        {
            writer.WriteUInt32(columns);
            writer.WriteUInt32(rows);
            writer.WriteUInt32(widthPixels);
            writer.WriteUInt32(heightPixels);
        });
        await _channel.SendRequestAsync(WindowChangeRequest, wantReply: false, payload, cancellationToken).ConfigureAwait(false);
    }

    private void OnRequestReceived(object? sender, SshChannelRequestEventArgs e)
    {
        switch (e.RequestType)
        {
            case ExitStatusRequest:
                RaiseExitStatus(e.RequestData.Span);
                break;
            case ExitSignalRequest:
                RaiseExitSignal(e.RequestData.Span);
                break;
        }
    }

    private void RaiseExitStatus(ReadOnlySpan<byte> data)
    {
        try
        {
            SshWireReader reader = new SshWireReader(data);
            uint exitCode = reader.ReadUInt32();
            ExitStatusReceived?.Invoke(this, new SshChannelExitStatusEventArgs(exitCode));
        }
        catch (SshWireFormatException)
        {
            // A malformed exit-status is non-fatal to the channel; ignore.
        }
    }

    private void RaiseExitSignal(ReadOnlySpan<byte> data)
    {
        try
        {
            SshWireReader reader = new SshWireReader(data);
            string signalName = reader.ReadText();
            bool coreDumped = reader.ReadBoolean();
            string errorMessage = reader.ReadText();
            ExitSignalReceived?.Invoke(this, new SshChannelExitSignalEventArgs(signalName, coreDumped, errorMessage));
        }
        catch (SshWireFormatException)
        {
            // A malformed exit-signal is non-fatal to the channel; ignore.
        }
    }

    private static byte[] BuildPayload(SshWireWriteCallback write)
    {
        using PooledBufferWriter writer = new PooledBufferWriter(64);
        SshWireWriter wire = new SshWireWriter(writer);
        write(ref wire);
        return writer.WrittenSpan.ToArray();
    }

    private delegate void SshWireWriteCallback(ref SshWireWriter writer);
}
