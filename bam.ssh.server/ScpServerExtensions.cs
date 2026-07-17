using Bam.Ssh.Scp;
using Bam.Ssh.Sftp;

namespace Bam.Ssh.Server;

/// <summary>
/// Wires SCP into an <see cref="SshServer"/>: <c>MapScp</c> registers the <c>exec</c> handler that services a
/// peer's <c>scp -t</c> (receive) and <c>scp -f</c> (send) over the same <see cref="ISftpFileSystem"/> the
/// SFTP subsystem uses. Because SCP rides <c>exec</c> (there is no dedicated subsystem name), <c>MapScp</c>
/// claims the server's single exec handler; a non-<c>scp</c> exec is answered with an error and a non-zero
/// exit. Use the shared-filesystem overload for one filesystem across all connections, or the factory
/// overload to give each authenticated session its own (for example a per-user jailed root).
/// </summary>
public static class ScpServerExtensions
{
    /// <summary>
    /// Maps SCP over <c>exec</c> to a single shared filesystem.
    /// </summary>
    /// <param name="server">The server to configure.</param>
    /// <param name="fileSystem">The filesystem all sessions share.</param>
    /// <exception cref="ArgumentNullException">The server or filesystem is null.</exception>
    public static void MapScp(this SshServer server, ISftpFileSystem fileSystem)
    {
        ArgumentNullException.ThrowIfNull(server);
        ArgumentNullException.ThrowIfNull(fileSystem);
        server.MapScp(context => fileSystem);
    }

    /// <summary>
    /// Maps SCP over <c>exec</c>, choosing the filesystem per session from the command context (for example a
    /// per-user root).
    /// </summary>
    /// <param name="server">The server to configure.</param>
    /// <param name="fileSystemFactory">Produces the filesystem for a started exec channel.</param>
    /// <exception cref="ArgumentNullException">The server or factory is null.</exception>
    public static void MapScp(this SshServer server, Func<SshServerCommandContext, ISftpFileSystem> fileSystemFactory)
    {
        ArgumentNullException.ThrowIfNull(server);
        ArgumentNullException.ThrowIfNull(fileSystemFactory);
        server.MapExec(async (context, cancellationToken) =>
        {
            if (!ScpCommand.IsScpCommand(context.CommandLine))
            {
                await context.WriteErrorAsync($"exec of '{context.CommandLine}' is not supported.\n", cancellationToken).ConfigureAwait(false);
                await context.ExitAsync(127, cancellationToken).ConfigureAwait(false);
                return;
            }

            ScpProtocol protocol = new ScpProtocol(new SshServerCommandContextScpChannel(context));
            try
            {
                ScpCommand command = ScpCommand.Parse(context.CommandLine);
                ISftpFileSystem fileSystem = fileSystemFactory(context);
                if (command.Mode == ScpTransferMode.Sink)
                {
                    ScpReceiver receiver = new ScpReceiver(protocol, fileSystem);
                    await receiver.ReceiveAsync(command.Path, cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    ScpSender sender = new ScpSender(protocol, fileSystem);
                    await sender.SendAsync(command.Path, command.Recursive, command.PreserveTimes, cancellationToken).ConfigureAwait(false);
                }

                await context.ExitAsync(0, cancellationToken).ConfigureAwait(false);
            }
            catch (ScpException ex)
            {
                await FailAsync(context, protocol, ex.Message, cancellationToken).ConfigureAwait(false);
            }
            catch (SftpStatusException ex)
            {
                await FailAsync(context, protocol, ex.Message, cancellationToken).ConfigureAwait(false);
            }
        });
    }

    private static async Task FailAsync(SshServerCommandContext context, ScpProtocol protocol, string message, CancellationToken cancellationToken)
    {
        // Best-effort: tell the peer over the SCP channel and stderr, then exit non-zero.
        try
        {
            await protocol.WriteErrorAsync(message, cancellationToken).ConfigureAwait(false);
        }
        catch (SshException)
        {
        }

        try
        {
            await context.WriteErrorAsync(string.Concat(message, "\n"), cancellationToken).ConfigureAwait(false);
        }
        catch (SshException)
        {
        }

        await context.ExitAsync(1, cancellationToken).ConfigureAwait(false);
    }
}
