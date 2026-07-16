namespace Bam.Ssh.Connection;

/// <summary>
/// The payload of an <c>exit-signal</c> channel request (RFC 4254 §6.10): the remote command was
/// terminated by a signal rather than exiting normally.
/// </summary>
public sealed class SshChannelExitSignalEventArgs : EventArgs
{
    /// <summary>
    /// Initializes the event data.
    /// </summary>
    /// <param name="signalName">The signal name without the SIG prefix (e.g. <c>TERM</c>).</param>
    /// <param name="coreDumped">Whether the remote process dumped core.</param>
    /// <param name="errorMessage">A human-readable message describing the termination.</param>
    /// <exception cref="ArgumentNullException">The signal name or error message is null.</exception>
    public SshChannelExitSignalEventArgs(string signalName, bool coreDumped, string errorMessage)
    {
        ArgumentNullException.ThrowIfNull(signalName);
        ArgumentNullException.ThrowIfNull(errorMessage);
        SignalName = signalName;
        CoreDumped = coreDumped;
        ErrorMessage = errorMessage;
    }

    /// <summary>
    /// Gets the signal name without the SIG prefix.
    /// </summary>
    public string SignalName { get; }

    /// <summary>
    /// Gets whether the remote process dumped core.
    /// </summary>
    public bool CoreDumped { get; }

    /// <summary>
    /// Gets the human-readable termination message.
    /// </summary>
    public string ErrorMessage { get; }
}
