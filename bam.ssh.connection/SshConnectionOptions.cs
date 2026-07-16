namespace Bam.Ssh.Connection;

/// <summary>
/// Tunable parameters for a <see cref="SshConnection"/>: the initial per-channel flow-control window,
/// the maximum channel packet size advertised to the peer, and the byte/time thresholds that trigger
/// an automatic re-key (RFC 4253 §9). Immutable; construct once and share.
/// </summary>
public sealed class SshConnectionOptions
{
    /// <summary>
    /// The default initial window size advertised for each opened channel (2 MiB), matching common
    /// SSH implementations.
    /// </summary>
    public const int DefaultInitialWindowSize = 2 * 1024 * 1024;

    /// <summary>
    /// The default maximum channel packet size advertised to the peer (32 KiB).
    /// </summary>
    public const int DefaultMaximumPacketSize = 32 * 1024;

    /// <summary>
    /// The default number of bytes sent or received before an automatic re-key is requested (1 GiB),
    /// the RFC 4253 §9 recommendation.
    /// </summary>
    public const long DefaultRekeyBytes = 1024L * 1024L * 1024L;

    /// <summary>
    /// A shared instance with all defaults.
    /// </summary>
    public static readonly SshConnectionOptions Default = new SshConnectionOptions();

    /// <summary>
    /// Initializes the options.
    /// </summary>
    /// <param name="initialWindowSize">The initial per-channel receive window; defaults to <see cref="DefaultInitialWindowSize"/>.</param>
    /// <param name="maximumPacketSize">The maximum channel packet size; defaults to <see cref="DefaultMaximumPacketSize"/>.</param>
    /// <param name="rekeyBytes">The transferred-byte threshold that triggers a re-key; defaults to <see cref="DefaultRekeyBytes"/>.</param>
    /// <param name="rekeyInterval">The elapsed-time threshold that triggers a re-key; defaults to one hour.</param>
    /// <exception cref="ArgumentOutOfRangeException">A size or threshold is not positive.</exception>
    public SshConnectionOptions(
        int initialWindowSize = DefaultInitialWindowSize,
        int maximumPacketSize = DefaultMaximumPacketSize,
        long rekeyBytes = DefaultRekeyBytes,
        TimeSpan? rekeyInterval = null)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(initialWindowSize);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumPacketSize);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(rekeyBytes);
        InitialWindowSize = initialWindowSize;
        MaximumPacketSize = maximumPacketSize;
        RekeyBytes = rekeyBytes;
        RekeyInterval = rekeyInterval ?? TimeSpan.FromHours(1);
    }

    /// <summary>
    /// Gets the initial per-channel receive window advertised to the peer.
    /// </summary>
    public int InitialWindowSize { get; }

    /// <summary>
    /// Gets the maximum channel packet size advertised to the peer.
    /// </summary>
    public int MaximumPacketSize { get; }

    /// <summary>
    /// Gets the number of transferred bytes (in either direction) after which a re-key is requested.
    /// </summary>
    public long RekeyBytes { get; }

    /// <summary>
    /// Gets the elapsed time after which a re-key is requested.
    /// </summary>
    public TimeSpan RekeyInterval { get; }
}
