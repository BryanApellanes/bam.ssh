namespace Bam.Ssh.Connection;

/// <summary>
/// The payload of an <c>exit-status</c> channel request (RFC 4254 §6.10): the exit code the remote
/// command returned.
/// </summary>
public sealed class SshChannelExitStatusEventArgs : EventArgs
{
    /// <summary>
    /// Initializes the event data.
    /// </summary>
    /// <param name="exitCode">The remote command's exit code.</param>
    public SshChannelExitStatusEventArgs(uint exitCode)
    {
        ExitCode = exitCode;
    }

    /// <summary>
    /// Gets the remote command's exit code.
    /// </summary>
    public uint ExitCode { get; }
}
