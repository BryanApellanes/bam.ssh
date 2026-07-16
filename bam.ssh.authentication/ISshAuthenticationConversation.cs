namespace Bam.Ssh.Authentication;

/// <summary>
/// The narrow seam an <see cref="ISshAuthenticationMethod"/> uses to carry out its request/reply
/// dialog without owning the transport or duplicating the generic reply handling. The orchestrator
/// (<see cref="SshUserAuthenticator"/>) implements this: it frames the SSH_MSG_USERAUTH_REQUEST header
/// (user name, service name, method name) around the method's fields, and classifies each reply,
/// transparently absorbing banners. A method reads <see cref="SessionId"/>, <see cref="UserName"/>,
/// and <see cref="ServiceName"/> to build any data it must sign.
/// </summary>
public interface ISshAuthenticationConversation
{
    /// <summary>Gets the session identifier a publickey signature binds to (RFC 4252 §7).</summary>
    ReadOnlyMemory<byte> SessionId { get; }

    /// <summary>Gets the user name being authenticated.</summary>
    string UserName { get; }

    /// <summary>Gets the service name requested after authentication (always <c>ssh-connection</c>).</summary>
    string ServiceName { get; }

    /// <summary>
    /// Sends an SSH_MSG_USERAUTH_REQUEST whose header is <c>user name || service name || method
    /// name</c> and whose remainder is the method-specific fields.
    /// </summary>
    /// <param name="methodName">The authentication method name (e.g. <c>publickey</c>).</param>
    /// <param name="methodFields">The method-specific fields that follow the method name.</param>
    /// <param name="cancellationToken">Cancels the send.</param>
    /// <returns>A task that completes when the request has been written and flushed.</returns>
    ValueTask SendRequestAsync(string methodName, ReadOnlyMemory<byte> methodFields, CancellationToken cancellationToken = default);

    /// <summary>
    /// Sends a method-specific message (60–79) whose payload is the message-number byte followed by the
    /// given body — used, for example, for the keyboard-interactive SSH_MSG_USERAUTH_INFO_RESPONSE (61).
    /// </summary>
    /// <param name="messageNumber">The method-specific message number.</param>
    /// <param name="body">The message body that follows the message-number byte.</param>
    /// <param name="cancellationToken">Cancels the send.</param>
    /// <returns>A task that completes when the message has been written and flushed.</returns>
    ValueTask SendMethodSpecificAsync(byte messageNumber, ReadOnlyMemory<byte> body, CancellationToken cancellationToken = default);

    /// <summary>
    /// Receives and classifies the next authentication reply, transparently surfacing and consuming any
    /// SSH_MSG_USERAUTH_BANNER before returning the next non-banner reply.
    /// </summary>
    /// <param name="cancellationToken">Cancels the receive.</param>
    /// <returns>The classified reply.</returns>
    /// <exception cref="SshAuthenticationException">The reply was malformed or of an unexpected type.</exception>
    ValueTask<SshAuthenticationReply> ReceiveReplyAsync(CancellationToken cancellationToken = default);
}
