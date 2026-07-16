namespace Bam.Ssh.Connection;

/// <summary>
/// Describes a channel to open with SSH_MSG_CHANNEL_OPEN (RFC 4254 §5.1): the channel type, this
/// side's advertised initial window and maximum packet size, and any channel-type-specific opening
/// data that follows the common fields (empty for a <c>session</c> channel).
/// </summary>
public sealed class SshChannelOpenParameters
{
    /// <summary>
    /// The channel type name for an interactive/command session channel.
    /// </summary>
    public const string SessionChannelType = "session";

    /// <summary>
    /// Initializes the parameters.
    /// </summary>
    /// <param name="channelType">The channel type name (e.g. <c>session</c>).</param>
    /// <param name="initialWindowSize">This side's initial receive window for the channel.</param>
    /// <param name="maximumPacketSize">The largest channel packet this side will accept.</param>
    /// <param name="typeSpecificData">The channel-type-specific opening bytes; empty when there are none.</param>
    /// <exception cref="ArgumentNullException">The channel type or type-specific data is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">A size is not positive.</exception>
    public SshChannelOpenParameters(
        string channelType,
        int initialWindowSize,
        int maximumPacketSize,
        ReadOnlyMemory<byte> typeSpecificData = default)
    {
        ArgumentNullException.ThrowIfNull(channelType);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(initialWindowSize);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumPacketSize);
        ChannelType = channelType;
        InitialWindowSize = initialWindowSize;
        MaximumPacketSize = maximumPacketSize;
        TypeSpecificData = typeSpecificData;
    }

    /// <summary>
    /// Gets the channel type name.
    /// </summary>
    public string ChannelType { get; }

    /// <summary>
    /// Gets this side's initial receive window for the channel.
    /// </summary>
    public int InitialWindowSize { get; }

    /// <summary>
    /// Gets the largest channel packet this side will accept.
    /// </summary>
    public int MaximumPacketSize { get; }

    /// <summary>
    /// Gets the channel-type-specific opening bytes (empty for a session channel).
    /// </summary>
    public ReadOnlyMemory<byte> TypeSpecificData { get; }

    /// <summary>
    /// Creates parameters for a <c>session</c> channel using the given connection options for its
    /// window and packet size.
    /// </summary>
    /// <param name="options">The connection options supplying the window and packet size.</param>
    /// <returns>The session-channel open parameters.</returns>
    /// <exception cref="ArgumentNullException">The options are null.</exception>
    public static SshChannelOpenParameters Session(SshConnectionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        return new SshChannelOpenParameters(SessionChannelType, options.InitialWindowSize, options.MaximumPacketSize);
    }
}
