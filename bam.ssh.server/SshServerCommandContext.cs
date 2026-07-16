using System.Text;
using Bam.Ssh.Connection;

namespace Bam.Ssh.Server;

/// <summary>
/// The server-side view of one started <c>session</c> channel handed to a mapped command handler: who
/// authenticated, what they asked to run, and the three byte streams — read the peer's standard input with
/// <see cref="ReadAsync(Memory{byte}, CancellationToken)"/>, write standard output with
/// <see cref="WriteAsync(ReadOnlyMemory{byte}, CancellationToken)"/>, and standard error with
/// <see cref="WriteErrorAsync(ReadOnlyMemory{byte}, CancellationToken)"/>. When the handler returns, the
/// session finalizes the channel with an <c>exit-status</c> of zero unless the handler set one with
/// <see cref="ExitAsync"/>; the handler may exit early to report a non-zero code.
/// </summary>
public sealed class SshServerCommandContext
{
    private readonly SshChannel _channel;
    private bool _completed;

    internal SshServerCommandContext(
        SshChannel channel,
        string userName,
        SshServerCommandType commandType,
        string commandLine,
        string subsystemName)
    {
        _channel = channel;
        UserName = userName;
        CommandType = commandType;
        CommandLine = commandLine;
        SubsystemName = subsystemName;
    }

    /// <summary>
    /// Gets the underlying channel for advanced use (custom requests, direct window control).
    /// </summary>
    public SshChannel Channel => _channel;

    /// <summary>
    /// Gets the authenticated user this command runs as.
    /// </summary>
    public string UserName { get; }

    /// <summary>
    /// Gets how the peer started the work (<c>exec</c>, <c>shell</c>, or <c>subsystem</c>).
    /// </summary>
    public SshServerCommandType CommandType { get; }

    /// <summary>
    /// Gets the command line for an <see cref="SshServerCommandType.Exec"/> request; empty otherwise.
    /// </summary>
    public string CommandLine { get; }

    /// <summary>
    /// Gets the subsystem name for an <see cref="SshServerCommandType.Subsystem"/> request; empty otherwise.
    /// </summary>
    public string SubsystemName { get; }

    /// <summary>
    /// Reads the peer's standard input (the channel's data stream) into the buffer.
    /// </summary>
    /// <param name="buffer">The destination buffer.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>The number of bytes read, or zero at end of stream.</returns>
    public ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        return _channel.ReadAsync(buffer, cancellationToken);
    }

    /// <summary>
    /// Writes to the peer's standard output (the channel's data stream).
    /// </summary>
    /// <param name="data">The bytes to write.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    public ValueTask WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
    {
        return _channel.WriteAsync(data, cancellationToken);
    }

    /// <summary>
    /// Writes UTF-8 text to the peer's standard output.
    /// </summary>
    /// <param name="text">The text to write.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <exception cref="ArgumentNullException">The text is null.</exception>
    public ValueTask WriteAsync(string text, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(text);
        return _channel.WriteAsync(Encoding.UTF8.GetBytes(text), cancellationToken);
    }

    /// <summary>
    /// Writes to the peer's standard error (SSH_MSG_CHANNEL_EXTENDED_DATA, SSH_EXTENDED_DATA_STDERR).
    /// </summary>
    /// <param name="data">The bytes to write.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    public ValueTask WriteErrorAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
    {
        return _channel.WriteExtendedAsync(SshExtendedDataType.StandardError, data, cancellationToken);
    }

    /// <summary>
    /// Writes UTF-8 text to the peer's standard error.
    /// </summary>
    /// <param name="text">The text to write.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <exception cref="ArgumentNullException">The text is null.</exception>
    public ValueTask WriteErrorAsync(string text, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(text);
        return _channel.WriteExtendedAsync(SshExtendedDataType.StandardError, Encoding.UTF8.GetBytes(text), cancellationToken);
    }

    /// <summary>
    /// Reports the command's exit code to the peer and closes the channel (<c>exit-status</c> then EOF then
    /// CHANNEL_CLOSE). Optional — the session finalizes with zero when the handler returns without calling
    /// this — but a handler that ends with a non-zero status must call it. Idempotent; the first call wins.
    /// </summary>
    /// <param name="exitCode">The process exit code to report.</param>
    /// <param name="cancellationToken">Cancels the finalization.</param>
    public ValueTask ExitAsync(int exitCode, CancellationToken cancellationToken = default)
    {
        return CompleteAsync(exitCode, cancellationToken);
    }

    internal async ValueTask CompleteAsync(int exitCode, CancellationToken cancellationToken)
    {
        if (_completed)
        {
            return;
        }
        _completed = true;

        using (PooledBufferWriter writer = new PooledBufferWriter(4))
        {
            SshWireWriter wire = new SshWireWriter(writer);
            wire.WriteUInt32(unchecked((uint)exitCode));
            await _channel.SendRequestAsync("exit-status", wantReply: false, writer.WrittenMemory, cancellationToken).ConfigureAwait(false);
        }
        await _channel.SendEofAsync(cancellationToken).ConfigureAwait(false);
        await _channel.CloseAsync(cancellationToken).ConfigureAwait(false);
    }
}
