using Bam.Ssh.Connection;
using Bam.Ssh.Transport;

namespace Bam.Ssh.Server;

/// <summary>
/// Immutable configuration for an <see cref="SshServer"/>: the advertised software version, connection
/// tunables, an optional pre-authentication banner, the listen backlog, and a cap on concurrent peer
/// connections. Construct once and reuse.
/// </summary>
public sealed class SshServerOptions
{
    /// <summary>
    /// The default software version advertised in the identification string.
    /// </summary>
    public const string DefaultSoftwareVersion = "Bam.Ssh_1.0";

    /// <summary>
    /// Initializes the options.
    /// </summary>
    /// <param name="connectionOptions">Connection tunables; defaults to <see cref="SshConnectionOptions.Default"/>.</param>
    /// <param name="softwareVersion">The advertised software version; defaults to <see cref="DefaultSoftwareVersion"/>.</param>
    /// <param name="banner">An optional banner sent before authentication; null (the default) sends none.</param>
    /// <param name="backlog">The listen backlog for the accept socket; defaults to 128.</param>
    /// <param name="maxConcurrentConnections">
    /// The maximum number of concurrently served peer connections; further accepts wait for a slot. Zero
    /// (the default) means unlimited.
    /// </param>
    /// <exception cref="ArgumentException">The software version is null or empty.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The backlog is negative or the connection cap is negative.</exception>
    public SshServerOptions(
        SshConnectionOptions? connectionOptions = null,
        string softwareVersion = DefaultSoftwareVersion,
        string? banner = null,
        int backlog = 128,
        int maxConcurrentConnections = 0)
    {
        ArgumentException.ThrowIfNullOrEmpty(softwareVersion);
        ArgumentOutOfRangeException.ThrowIfNegative(backlog);
        ArgumentOutOfRangeException.ThrowIfNegative(maxConcurrentConnections);
        ConnectionOptions = connectionOptions ?? SshConnectionOptions.Default;
        SoftwareVersion = softwareVersion;
        Banner = banner;
        Backlog = backlog;
        MaxConcurrentConnections = maxConcurrentConnections;
    }

    /// <summary>
    /// Gets the connection tunables.
    /// </summary>
    public SshConnectionOptions ConnectionOptions { get; }

    /// <summary>
    /// Gets the advertised software version.
    /// </summary>
    public string SoftwareVersion { get; }

    /// <summary>
    /// Gets the optional pre-authentication banner, or null when none is sent.
    /// </summary>
    public string? Banner { get; }

    /// <summary>
    /// Gets the listen backlog for the accept socket.
    /// </summary>
    public int Backlog { get; }

    /// <summary>
    /// Gets the concurrent-connection cap, or zero for unlimited.
    /// </summary>
    public int MaxConcurrentConnections { get; }

    internal SshTransportOptions ToTransportOptions()
    {
        return new SshTransportOptions(SoftwareVersion);
    }
}
