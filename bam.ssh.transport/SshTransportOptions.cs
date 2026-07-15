namespace Bam.Ssh.Transport;

/// <summary>
/// Immutable configuration for the transport layer: the software version advertised in the
/// identification string, the limits that bound the identification/banner exchange, and the packet
/// limits handed to the decoder. Construct once and share; nothing here changes per connection.
/// </summary>
public sealed class SshTransportOptions
{
    /// <summary>
    /// The default software version bam.ssh advertises when none is supplied.
    /// </summary>
    public const string DefaultSoftwareVersion = "Bam.Ssh_1.0";

    /// <summary>
    /// The RFC 4253 §4.2 limit on the identification line length excluding CRLF.
    /// </summary>
    public const int DefaultMaxIdentificationLineLength = 255;

    /// <summary>
    /// The default cap on pre-identification banner lines a peer may send before its identification
    /// string, bounding memory use during the handshake.
    /// </summary>
    public const int DefaultMaxBannerLines = 1024;

    /// <summary>
    /// The default options: default software version, RFC line-length limit, default banner cap,
    /// and default packet limits.
    /// </summary>
    public static readonly SshTransportOptions Default = new SshTransportOptions();

    /// <summary>
    /// Initializes transport options.
    /// </summary>
    /// <param name="softwareVersion">The software version to advertise; must satisfy the RFC 4253 §4.2 rules. Defaults to <see cref="DefaultSoftwareVersion"/>.</param>
    /// <param name="maxIdentificationLineLength">The maximum accepted identification/banner line length excluding CRLF. Defaults to <see cref="DefaultMaxIdentificationLineLength"/>.</param>
    /// <param name="maxBannerLines">The maximum number of pre-identification banner lines to tolerate. Defaults to <see cref="DefaultMaxBannerLines"/>.</param>
    /// <param name="packetLimits">The packet limits passed to the decoder. Defaults to <see cref="SshPacketLimits.Default"/>.</param>
    /// <exception cref="ArgumentOutOfRangeException">A limit is not positive.</exception>
    public SshTransportOptions(
        string softwareVersion = DefaultSoftwareVersion,
        int maxIdentificationLineLength = DefaultMaxIdentificationLineLength,
        int maxBannerLines = DefaultMaxBannerLines,
        SshPacketLimits? packetLimits = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(softwareVersion);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxIdentificationLineLength, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxBannerLines, 0);
        SoftwareVersion = softwareVersion;
        MaxIdentificationLineLength = maxIdentificationLineLength;
        MaxBannerLines = maxBannerLines;
        PacketLimits = packetLimits ?? SshPacketLimits.Default;
    }

    /// <summary>
    /// Gets the software version advertised in the local identification string.
    /// </summary>
    public string SoftwareVersion { get; }

    /// <summary>
    /// Gets the maximum accepted identification/banner line length, excluding CRLF.
    /// </summary>
    public int MaxIdentificationLineLength { get; }

    /// <summary>
    /// Gets the maximum number of banner lines tolerated before the peer's identification string.
    /// </summary>
    public int MaxBannerLines { get; }

    /// <summary>
    /// Gets the packet limits enforced by the decoder.
    /// </summary>
    public SshPacketLimits PacketLimits { get; }

    /// <summary>
    /// Builds the local identification string from these options.
    /// </summary>
    /// <returns>The identification string advertising protocol 2.0 and the configured software version.</returns>
    public SshIdentificationString CreateLocalIdentification()
    {
        return new SshIdentificationString(SshIdentificationString.SupportedProtocolVersion, SoftwareVersion);
    }
}
