using Bam.Ssh.Transport;

namespace Bam.Ssh.Client;

/// <summary>
/// The inputs to a host-key trust decision (see <see cref="ISshHostKeyVerifier"/>): the host and port
/// being connected to, and the server's cryptographically verified host key (its algorithm, fingerprint,
/// and raw blob are available for matching or display).
/// </summary>
public sealed class SshHostKeyVerificationContext
{
    /// <summary>
    /// Initializes the verification context.
    /// </summary>
    /// <param name="host">The host name or address being connected to.</param>
    /// <param name="port">The port being connected to.</param>
    /// <param name="hostKey">The server's verified host key.</param>
    /// <exception cref="ArgumentNullException">The host or host key is null.</exception>
    public SshHostKeyVerificationContext(string host, int port, ISshHostKey hostKey)
    {
        ArgumentNullException.ThrowIfNull(host);
        ArgumentNullException.ThrowIfNull(hostKey);
        Host = host;
        Port = port;
        HostKey = hostKey;
    }

    /// <summary>
    /// Gets the host name or address being connected to.
    /// </summary>
    public string Host { get; }

    /// <summary>
    /// Gets the port being connected to.
    /// </summary>
    public int Port { get; }

    /// <summary>
    /// Gets the server's verified host key.
    /// </summary>
    public ISshHostKey HostKey { get; }
}
