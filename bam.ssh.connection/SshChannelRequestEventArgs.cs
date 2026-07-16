namespace Bam.Ssh.Connection;

/// <summary>
/// Describes an inbound SSH_MSG_CHANNEL_REQUEST (RFC 4254 §5.4) that the generic channel did not
/// interpret itself: the request type name, whether the peer wants a reply, and the request-specific
/// bytes that follow. Higher layers (e.g. <see cref="SshSessionChannel"/>) parse the request-specific
/// bytes according to the type.
/// </summary>
public sealed class SshChannelRequestEventArgs : EventArgs
{
    /// <summary>
    /// Initializes the event data.
    /// </summary>
    /// <param name="requestType">The request type name (e.g. <c>exit-status</c>).</param>
    /// <param name="wantReply">Whether the peer requested a CHANNEL_SUCCESS/FAILURE reply.</param>
    /// <param name="requestData">The request-type-specific bytes following the common fields.</param>
    /// <exception cref="ArgumentNullException">The request type is null.</exception>
    public SshChannelRequestEventArgs(string requestType, bool wantReply, ReadOnlyMemory<byte> requestData)
    {
        ArgumentNullException.ThrowIfNull(requestType);
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
}
