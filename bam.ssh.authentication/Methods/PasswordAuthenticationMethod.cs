namespace Bam.Ssh.Authentication;

/// <summary>
/// The <c>password</c> authentication method (RFC 4252 §8). Sends the user's password in the clear
/// (protected by the encrypted transport) as <c>boolean FALSE || string password</c>. If the server
/// replies SSH_MSG_USERAUTH_PASSWD_CHANGEREQ (a required password change), this method reports a
/// failure rather than driving the change dialog, which is out of scope for this phase.
/// </summary>
public sealed class PasswordAuthenticationMethod : ISshAuthenticationMethod
{
    private readonly string _password;

    /// <summary>
    /// Initializes the method with the password to send.
    /// </summary>
    /// <param name="password">The user's password.</param>
    /// <exception cref="ArgumentNullException">The password is null.</exception>
    public PasswordAuthenticationMethod(string password)
    {
        ArgumentNullException.ThrowIfNull(password);
        _password = password;
    }

    /// <inheritdoc/>
    public string MethodName => SshAuthenticationNames.Password;

    /// <inheritdoc/>
    public async ValueTask<SshAuthenticationReply> AttemptAsync(ISshAuthenticationConversation conversation, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(conversation);
        string password = _password;
        byte[] fields = SshSignatureBlob.Build((ref SshWireWriter writer) =>
        {
            writer.WriteBoolean(false);
            writer.WriteText(password);
        });

        await conversation.SendRequestAsync(MethodName, fields, cancellationToken).ConfigureAwait(false);
        SshAuthenticationReply reply = await conversation.ReceiveReplyAsync(cancellationToken).ConfigureAwait(false);
        if (reply.Kind == SshAuthenticationReplyKind.MethodSpecific &&
            reply.MessageNumber == SshUserAuthMessageNumber.PasswordChangeRequest)
        {
            // A required password change is not driven in this phase; treat it as a rejected attempt.
            return SshAuthenticationReply.CreateFailure(SshNameList.Empty, false);
        }
        return SshAuthenticationMethodSupport.EnsureTerminal(reply, MethodName);
    }
}
