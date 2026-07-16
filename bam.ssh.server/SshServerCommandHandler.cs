namespace Bam.Ssh.Server;

/// <summary>
/// Serves one started <c>session</c> channel: reads standard input, writes standard output and error, and
/// returns when the work is done. Returning normally finalizes the channel with an <c>exit-status</c> of
/// zero; call <see cref="SshServerCommandContext.ExitAsync"/> to report a different code. The handler runs
/// off the connection's receive-dispatch loop, so it may block on I/O without stalling other channels.
/// </summary>
/// <param name="context">The started channel's streams and request details.</param>
/// <param name="cancellationToken">Cancelled when the server stops or the connection ends.</param>
/// <returns>A task that completes when the handler is finished serving the channel.</returns>
public delegate Task SshServerCommandHandler(SshServerCommandContext context, CancellationToken cancellationToken);
