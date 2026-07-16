namespace Bam.Ssh.Connection;

/// <summary>
/// The inbound channel-open request handed to an <see cref="ISshChannelOpenHandler"/>: the requested
/// channel type and its type-specific bytes, plus the controls to <see cref="Accept"/> the channel
/// (creating a server-side <see cref="SshChannel"/> and confirming it) or <see cref="Reject"/> it. Exactly
/// one of accept/reject may be called.
/// </summary>
public sealed class SshChannelOpenRequestContext
{
    private readonly SshConnection _connection;
    private readonly uint _remoteId;
    private readonly uint _remoteWindow;
    private readonly uint _remoteMaximumPacket;
    private bool _resolved;

    internal SshChannelOpenRequestContext(
        SshConnection connection,
        string channelType,
        ReadOnlyMemory<byte> typeSpecificData,
        uint remoteId,
        uint remoteWindow,
        uint remoteMaximumPacket)
    {
        _connection = connection;
        ChannelType = channelType;
        TypeSpecificData = typeSpecificData;
        _remoteId = remoteId;
        _remoteWindow = remoteWindow;
        _remoteMaximumPacket = remoteMaximumPacket;
    }

    /// <summary>
    /// Gets the requested channel type name.
    /// </summary>
    public string ChannelType { get; }

    /// <summary>
    /// Gets the channel-type-specific opening bytes (empty for a session channel).
    /// </summary>
    public ReadOnlyMemory<byte> TypeSpecificData { get; }

    /// <summary>
    /// Gets whether the request has already been accepted or rejected.
    /// </summary>
    public bool Resolved => _resolved;

    /// <summary>
    /// Accepts the open, creating and confirming a server-side channel.
    /// </summary>
    /// <returns>The accepted channel, ready for I/O and requests.</returns>
    /// <exception cref="InvalidOperationException">The request was already resolved.</exception>
    public SshChannel Accept()
    {
        if (_resolved)
        {
            throw new InvalidOperationException("The channel-open request has already been resolved.");
        }
        _resolved = true;
        return _connection.AcceptInboundChannel(ChannelType, _remoteId, _remoteWindow, _remoteMaximumPacket);
    }

    /// <summary>
    /// Rejects the open with a reason.
    /// </summary>
    /// <param name="reason">The failure reason code.</param>
    /// <param name="description">A human-readable description.</param>
    /// <exception cref="InvalidOperationException">The request was already resolved.</exception>
    public void Reject(SshChannelOpenFailureReason reason, string description)
    {
        ArgumentNullException.ThrowIfNull(description);
        if (_resolved)
        {
            throw new InvalidOperationException("The channel-open request has already been resolved.");
        }
        _resolved = true;
        _connection.RejectInboundChannel(_remoteId, reason, description);
    }
}
