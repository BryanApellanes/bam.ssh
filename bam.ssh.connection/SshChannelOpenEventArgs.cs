namespace Bam.Ssh.Connection;

/// <summary>
/// Describes a peer-initiated SSH_MSG_CHANNEL_OPEN (RFC 4254 §5.1). In this phase the connection is a
/// client that opens its own channels, so it rejects inbound opens with
/// <see cref="SshChannelOpenFailureReason.UnknownChannelType"/> after raising this event; the server
/// role (accepting the open) is added in a later phase.
/// </summary>
public sealed class SshChannelOpenEventArgs : EventArgs
{
    /// <summary>
    /// Initializes the event data.
    /// </summary>
    /// <param name="channelType">The requested channel type name.</param>
    /// <param name="senderChannel">The peer's channel identifier.</param>
    /// <param name="initialWindowSize">The peer's initial send window.</param>
    /// <param name="maximumPacketSize">The peer's maximum packet size.</param>
    /// <exception cref="ArgumentNullException">The channel type is null.</exception>
    public SshChannelOpenEventArgs(string channelType, uint senderChannel, uint initialWindowSize, uint maximumPacketSize)
    {
        ArgumentNullException.ThrowIfNull(channelType);
        ChannelType = channelType;
        SenderChannel = senderChannel;
        InitialWindowSize = initialWindowSize;
        MaximumPacketSize = maximumPacketSize;
    }

    /// <summary>
    /// Gets the requested channel type name.
    /// </summary>
    public string ChannelType { get; }

    /// <summary>
    /// Gets the peer's channel identifier.
    /// </summary>
    public uint SenderChannel { get; }

    /// <summary>
    /// Gets the peer's initial send window.
    /// </summary>
    public uint InitialWindowSize { get; }

    /// <summary>
    /// Gets the peer's maximum packet size.
    /// </summary>
    public uint MaximumPacketSize { get; }
}
