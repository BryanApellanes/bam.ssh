namespace Bam.Ssh.Server;

/// <summary>
/// How the peer asked the server to start work on a <c>session</c> channel (RFC 4254 §6.5): a one-shot
/// command line (<c>exec</c>), the user's interactive shell (<c>shell</c>), or a named subsystem such as
/// <c>sftp</c> (<c>subsystem</c>).
/// </summary>
public enum SshServerCommandType
{
    /// <summary>
    /// The peer requested a single command line via <c>exec</c>. The command is available on
    /// <see cref="SshServerCommandContext.CommandLine"/>.
    /// </summary>
    Exec,

    /// <summary>
    /// The peer requested the user's default interactive shell via <c>shell</c>.
    /// </summary>
    Shell,

    /// <summary>
    /// The peer requested a named subsystem via <c>subsystem</c>. The name is available on
    /// <see cref="SshServerCommandContext.SubsystemName"/>.
    /// </summary>
    Subsystem,
}
