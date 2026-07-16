namespace Bam.Ssh.Server;

/// <summary>
/// The immutable set of command handlers an <see cref="SshServer"/> serves — the <c>exec</c> handler, the
/// <c>shell</c> handler, and the named <c>subsystem</c> handlers — captured once when the server starts so
/// every peer connection routes against the same fixed map without locking.
/// </summary>
internal sealed class SshServerCommandMap
{
    private readonly IReadOnlyDictionary<string, SshServerCommandHandler> _subsystems;

    public SshServerCommandMap(
        SshServerCommandHandler? exec,
        SshServerCommandHandler? shell,
        IReadOnlyDictionary<string, SshServerCommandHandler> subsystems)
    {
        Exec = exec;
        Shell = shell;
        _subsystems = subsystems;
    }

    public SshServerCommandHandler? Exec { get; }

    public SshServerCommandHandler? Shell { get; }

    public bool IsEmpty => Exec == null && Shell == null && _subsystems.Count == 0;

    public SshServerCommandHandler? Resolve(SshServerCommandType commandType, string argument)
    {
        switch (commandType)
        {
            case SshServerCommandType.Exec:
                return Exec;
            case SshServerCommandType.Shell:
                return Shell;
            case SshServerCommandType.Subsystem:
                return _subsystems.TryGetValue(argument, out SshServerCommandHandler? handler) ? handler : null;
            default:
                return null;
        }
    }
}
