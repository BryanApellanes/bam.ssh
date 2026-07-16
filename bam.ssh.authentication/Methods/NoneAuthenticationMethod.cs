namespace Bam.Ssh.Authentication;

/// <summary>
/// The <c>none</c> authentication method (RFC 4252 §5.2). Sending it is the standard way to learn which
/// authentications a server will accept: the server almost always replies SSH_MSG_USERAUTH_FAILURE
/// with the acceptable-method list (which the orchestrator surfaces), though a server configured to
/// require no authentication may reply SSH_MSG_USERAUTH_SUCCESS.
/// </summary>
public sealed class NoneAuthenticationMethod : ISshAuthenticationMethod
{
    /// <inheritdoc/>
    public string MethodName => SshAuthenticationNames.None;

    /// <inheritdoc/>
    public async ValueTask<SshAuthenticationReply> AttemptAsync(ISshAuthenticationConversation conversation, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(conversation);
        await conversation.SendRequestAsync(MethodName, ReadOnlyMemory<byte>.Empty, cancellationToken).ConfigureAwait(false);
        SshAuthenticationReply reply = await conversation.ReceiveReplyAsync(cancellationToken).ConfigureAwait(false);
        return SshAuthenticationMethodSupport.EnsureTerminal(reply, MethodName);
    }
}
