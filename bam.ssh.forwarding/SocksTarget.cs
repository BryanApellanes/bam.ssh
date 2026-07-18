namespace Bam.Ssh.Forwarding;

/// <summary>
/// The destination a SOCKS client asked a dynamic forwarder to connect to: the host (an address or a
/// domain name) and the port.
/// </summary>
public sealed class SocksTarget
{
    /// <summary>
    /// Initializes the target.
    /// </summary>
    /// <param name="host">The destination host (address or domain name).</param>
    /// <param name="port">The destination port.</param>
    /// <exception cref="ArgumentException">The host is null or empty.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The port is outside 0–65535.</exception>
    public SocksTarget(string host, int port)
    {
        ArgumentException.ThrowIfNullOrEmpty(host);
        ForwardingPort.Validate(port);
        Host = host;
        Port = port;
    }

    /// <summary>
    /// Gets the destination host.
    /// </summary>
    public string Host { get; }

    /// <summary>
    /// Gets the destination port.
    /// </summary>
    public int Port { get; }
}
