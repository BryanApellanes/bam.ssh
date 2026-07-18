namespace Bam.Ssh.Forwarding;

/// <summary>
/// The RFC 4254 §7 channel-type and global-request names used by TCP/IP forwarding.
/// </summary>
public static class SshForwardingNames
{
    /// <summary>
    /// The channel type a client opens to ask the peer to connect to a target (local/dynamic forwarding).
    /// </summary>
    public const string DirectTcpIp = "direct-tcpip";

    /// <summary>
    /// The channel type a server opens when a connection arrives on a remote-forwarded port.
    /// </summary>
    public const string ForwardedTcpIp = "forwarded-tcpip";

    /// <summary>
    /// The global request that asks the peer to listen on a port and forward connections back (remote forwarding).
    /// </summary>
    public const string TcpIpForward = "tcpip-forward";

    /// <summary>
    /// The global request that cancels a previous <see cref="TcpIpForward"/>.
    /// </summary>
    public const string CancelTcpIpForward = "cancel-tcpip-forward";
}
