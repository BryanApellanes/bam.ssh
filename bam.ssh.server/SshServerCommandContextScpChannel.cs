using Bam.Ssh.Scp;

namespace Bam.Ssh.Server;

/// <summary>
/// Adapts a served <see cref="SshServerCommandContext"/> (a started <c>exec scp -t</c>/<c>scp -f</c> channel)
/// to the SCP byte-channel seam so a <see cref="ScpSender"/>/<see cref="ScpReceiver"/> can service it: reads
/// are the peer's standard input and writes are standard output.
/// </summary>
public sealed class SshServerCommandContextScpChannel : IScpChannel
{
    private readonly SshServerCommandContext _context;

    /// <summary>
    /// Initializes the adapter over a command context.
    /// </summary>
    /// <param name="context">The started exec channel's context.</param>
    /// <exception cref="ArgumentNullException">The context is null.</exception>
    public SshServerCommandContextScpChannel(SshServerCommandContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        _context = context;
    }

    /// <inheritdoc/>
    public ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        return _context.ReadAsync(buffer, cancellationToken);
    }

    /// <inheritdoc/>
    public ValueTask WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
    {
        return _context.WriteAsync(data, cancellationToken);
    }
}
