namespace Bam.Ssh.Connection;

/// <summary>
/// The inbound global request handed to an <see cref="ISshGlobalRequestHandler"/>: the request name and its
/// request-specific bytes, plus the controls to <see cref="Accept"/> it (optionally with reply bytes such as
/// a bound port) or <see cref="Reject"/> it. A reply is written only when the peer set <c>want_reply</c>.
/// Exactly one of accept/reject may be called.
/// </summary>
public sealed class SshGlobalRequestContext
{
    private readonly SshConnection _connection;
    private readonly bool _wantReply;
    private bool _resolved;

    internal SshGlobalRequestContext(SshConnection connection, string requestName, ReadOnlyMemory<byte> requestData, bool wantReply)
    {
        _connection = connection;
        RequestName = requestName;
        RequestData = requestData;
        _wantReply = wantReply;
    }

    /// <summary>
    /// Gets the global request name.
    /// </summary>
    public string RequestName { get; }

    /// <summary>
    /// Gets the request-specific bytes that follow the name and <c>want_reply</c> flag.
    /// </summary>
    public ReadOnlyMemory<byte> RequestData { get; }

    /// <summary>
    /// Gets whether the peer requested a reply.
    /// </summary>
    public bool WantReply => _wantReply;

    /// <summary>
    /// Gets whether the request has already been accepted or rejected.
    /// </summary>
    public bool Resolved => _resolved;

    /// <summary>
    /// Accepts the request. When the peer wanted a reply, sends SSH_MSG_REQUEST_SUCCESS followed by
    /// <paramref name="replyData"/> (empty for requests that carry no reply payload).
    /// </summary>
    /// <param name="replyData">The request-specific reply bytes (for example a bound port).</param>
    /// <exception cref="InvalidOperationException">The request was already resolved.</exception>
    public void Accept(ReadOnlyMemory<byte> replyData = default)
    {
        if (_resolved)
        {
            throw new InvalidOperationException("The global request has already been resolved.");
        }
        _resolved = true;
        if (_wantReply)
        {
            _connection.PostGlobalRequestSuccess(replyData.Span);
        }
    }

    /// <summary>
    /// Rejects the request, sending SSH_MSG_REQUEST_FAILURE when the peer wanted a reply.
    /// </summary>
    /// <exception cref="InvalidOperationException">The request was already resolved.</exception>
    public void Reject()
    {
        if (_resolved)
        {
            throw new InvalidOperationException("The global request has already been resolved.");
        }
        _resolved = true;
        if (_wantReply)
        {
            _connection.PostGlobalRequestFailure();
        }
    }
}
