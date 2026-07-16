using Bam.Ssh.Connection;
using Bam.Ssh.Transport;

namespace Bam.Ssh.Client;

/// <summary>
/// Immutable configuration for an <see cref="SshClient"/>: the host-key trust policy, connection tunables,
/// the advertised software version, and the optional keep-alive interval. Construct once and reuse.
/// </summary>
public sealed class SshClientOptions
{
    /// <summary>
    /// The default software version advertised in the identification string.
    /// </summary>
    public const string DefaultSoftwareVersion = "Bam.Ssh_1.0";

    /// <summary>
    /// Initializes the options.
    /// </summary>
    /// <param name="hostKeyVerifier">
    /// The host-key trust policy; defaults to a trust-on-first-use <see cref="KnownHostsHostKeyVerifier"/>
    /// over the user's <c>~/.ssh/known_hosts</c> (matching interactive <c>ssh</c>'s first-connect behavior).
    /// </param>
    /// <param name="connectionOptions">Connection tunables; defaults to <see cref="SshConnectionOptions.Default"/>.</param>
    /// <param name="softwareVersion">The advertised software version; defaults to <see cref="DefaultSoftwareVersion"/>.</param>
    /// <param name="keepAliveInterval">
    /// How often to send a <c>keepalive@openssh.com</c> global request once authenticated; null (the
    /// default) disables keep-alive.
    /// </param>
    /// <exception cref="ArgumentException">The software version is null or empty.</exception>
    public SshClientOptions(
        ISshHostKeyVerifier? hostKeyVerifier = null,
        SshConnectionOptions? connectionOptions = null,
        string softwareVersion = DefaultSoftwareVersion,
        TimeSpan? keepAliveInterval = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(softwareVersion);
        HostKeyVerifier = hostKeyVerifier ?? KnownHostsHostKeyVerifier.Tofu(KnownHostsHostKeyVerifier.DefaultPath());
        ConnectionOptions = connectionOptions ?? SshConnectionOptions.Default;
        SoftwareVersion = softwareVersion;
        KeepAliveInterval = keepAliveInterval;
    }

    /// <summary>
    /// Gets the host-key trust policy.
    /// </summary>
    public ISshHostKeyVerifier HostKeyVerifier { get; }

    /// <summary>
    /// Gets the connection tunables.
    /// </summary>
    public SshConnectionOptions ConnectionOptions { get; }

    /// <summary>
    /// Gets the advertised software version.
    /// </summary>
    public string SoftwareVersion { get; }

    /// <summary>
    /// Gets the keep-alive interval, or null when keep-alive is disabled.
    /// </summary>
    public TimeSpan? KeepAliveInterval { get; }

    internal SshTransportOptions ToTransportOptions()
    {
        return new SshTransportOptions(SoftwareVersion);
    }
}
