using Bam.Ssh.Sftp;
using Bam.Ssh.Transport;

namespace Bam.Ssh.Server;

/// <summary>
/// Wires the SFTP subsystem into an <see cref="SshServer"/>: <c>MapSftp</c> registers the <c>sftp</c>
/// subsystem handler that runs an <see cref="SftpServer"/> over each started channel, backed by a virtual
/// filesystem. Use the shared-filesystem overload for one filesystem across all connections, or the factory
/// overload to give each authenticated session its own (for example a per-user jailed root).
/// </summary>
public static class SftpServerExtensions
{
    /// <summary>
    /// Maps the <c>sftp</c> subsystem to a single shared filesystem.
    /// </summary>
    /// <param name="server">The server to configure.</param>
    /// <param name="fileSystem">The filesystem all sessions share.</param>
    /// <param name="logger">The logger for the SFTP engine; defaults to <see cref="NullSshLogger.Instance"/>.</param>
    /// <exception cref="ArgumentNullException">The server or filesystem is null.</exception>
    public static void MapSftp(this SshServer server, ISftpFileSystem fileSystem, ISshLogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(server);
        ArgumentNullException.ThrowIfNull(fileSystem);
        server.MapSftp(context => fileSystem, logger);
    }

    /// <summary>
    /// Maps the <c>sftp</c> subsystem, choosing the filesystem per session from the command context (for
    /// example a per-user root).
    /// </summary>
    /// <param name="server">The server to configure.</param>
    /// <param name="fileSystemFactory">Produces the filesystem for a started subsystem channel.</param>
    /// <param name="logger">The logger for the SFTP engine; defaults to <see cref="NullSshLogger.Instance"/>.</param>
    /// <exception cref="ArgumentNullException">The server or factory is null.</exception>
    public static void MapSftp(this SshServer server, Func<SshServerCommandContext, ISftpFileSystem> fileSystemFactory, ISshLogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(server);
        ArgumentNullException.ThrowIfNull(fileSystemFactory);
        server.MapSubsystem("sftp", async (context, cancellationToken) =>
        {
            ISftpFileSystem fileSystem = fileSystemFactory(context);
            SftpServer engine = new SftpServer(new SshServerCommandContextSftpChannel(context), fileSystem, logger);
            await engine.RunAsync(cancellationToken).ConfigureAwait(false);
        });
    }
}
