namespace Bam.Ssh.Client;

/// <summary>
/// Thrown when an <see cref="SshClient"/> operation is invoked in a state that does not permit it — for
/// example running a command before authenticating, or connecting a client that is already connected.
/// </summary>
public sealed class SshConnectionStateException : SshException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="SshConnectionStateException"/> class with a message.
    /// </summary>
    /// <param name="message">A description of the invalid state transition.</param>
    public SshConnectionStateException(string message) : base(message)
    {
    }
}
