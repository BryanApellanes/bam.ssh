namespace Bam.Ssh.Connection;

/// <summary>
/// Describes an inbound SSH_MSG_CHANNEL_REQUEST (RFC 4254 §5.4) that the generic channel did not
/// interpret itself: the request type name, whether the peer wants a reply, and the request-specific
/// bytes that follow. Higher layers (e.g. <see cref="SshSessionChannel"/>) parse the request-specific
/// bytes according to the type.
/// </summary>
public sealed class SshChannelRequestEventArgs : EventArgs
{
    private readonly SshChannel _channel;
    private bool _replied;

    internal SshChannelRequestEventArgs(SshChannel channel, string requestType, bool wantReply, ReadOnlyMemory<byte> requestData)
    {
        ArgumentNullException.ThrowIfNull(channel);
        ArgumentNullException.ThrowIfNull(requestType);
        _channel = channel;
        RequestType = requestType;
        WantReply = wantReply;
        RequestData = requestData;
    }

    /// <summary>
    /// Gets the request type name.
    /// </summary>
    public string RequestType { get; }

    /// <summary>
    /// Gets whether the peer requested a reply.
    /// </summary>
    public bool WantReply { get; }

    /// <summary>
    /// Gets the request-type-specific bytes.
    /// </summary>
    public ReadOnlyMemory<byte> RequestData { get; }

    /// <summary>
    /// Gets whether a reply has been sent for this request.
    /// </summary>
    public bool WasReplied => _replied;

    /// <summary>
    /// Replies to the request (a server role accepting or refusing it). Only meaningful when
    /// <see cref="WantReply"/> is set; the first call wins. If a handler leaves a <c>want_reply</c>
    /// request unanswered, the channel replies with failure automatically.
    /// </summary>
    /// <param name="success">True to send CHANNEL_SUCCESS, false to send CHANNEL_FAILURE.</param>
    public void Reply(bool success)
    {
        if (!WantReply || _replied)
        {
            return;
        }
        _replied = true;
        _channel.PostRequestReply(success);
    }
}
