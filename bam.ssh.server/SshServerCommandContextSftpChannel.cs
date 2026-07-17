using Bam.Ssh.Sftp;

namespace Bam.Ssh.Server;

/// <summary>
/// Adapts a served <see cref="SshServerCommandContext"/> (a started <c>subsystem sftp</c> channel) to the
/// SFTP byte-channel seam so an <see cref="SftpServer"/> can serve it: reads are the peer's standard input
/// and writes are standard output.
/// </summary>
public sealed class SshServerCommandContextSftpChannel : ISftpChannel
{
    private readonly SshServerCommandContext _context;

    /// <summary>
    /// Initializes the adapter over a command context.
    /// </summary>
    /// <param name="context">The started subsystem channel's context.</param>
    /// <exception cref="ArgumentNullException">The context is null.</exception>
    public SshServerCommandContextSftpChannel(SshServerCommandContext context)
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
