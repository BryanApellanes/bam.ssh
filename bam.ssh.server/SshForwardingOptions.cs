using Bam.Ssh.Forwarding;

namespace Bam.Ssh.Server;

/// <summary>
/// Configures which TCP/IP forwarding a server services for its peers, and the policies that gate it: local
/// (a peer's <c>direct-tcpip</c> connect requests) and remote (a peer's <c>tcpip-forward</c> listen requests),
/// each optionally filtered. Both are enabled by default when forwarding is turned on.
/// </summary>
public sealed class SshForwardingOptions
{
    /// <summary>
    /// Gets or sets whether the server honors <c>direct-tcpip</c> opens (the connect side of a peer's local
    /// and dynamic forwarding). Default true.
    /// </summary>
    public bool AllowLocalForwarding { get; set; } = true;

    /// <summary>
    /// Gets or sets whether the server honors <c>tcpip-forward</c> requests (the listen side of a peer's
    /// remote forwarding). Default true.
    /// </summary>
    public bool AllowRemoteForwarding { get; set; } = true;

    /// <summary>
    /// Gets or sets an optional policy that vetoes disallowed connect targets for local forwarding.
    /// </summary>
    public SshForwardingTargetFilter? TargetFilter { get; set; }

    /// <summary>
    /// Gets or sets an optional policy that vetoes disallowed binds for remote forwarding.
    /// </summary>
    public SshForwardingBindFilter? BindFilter { get; set; }
}
