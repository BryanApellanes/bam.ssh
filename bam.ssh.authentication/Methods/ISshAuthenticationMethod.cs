namespace Bam.Ssh.Authentication;

/// <summary>
/// One SSH authentication method (RFC 4252 §5) — the pluggable unit the orchestrator tries in order.
/// An implementation runs its own request/reply sub-dialog through the supplied
/// <see cref="ISshAuthenticationConversation"/> and returns the terminal reply, whose
/// <see cref="SshAuthenticationReply.Kind"/> is always <see cref="SshAuthenticationReplyKind.Success"/>
/// or <see cref="SshAuthenticationReplyKind.Failure"/>. Method-specific messages (60–79) are handled
/// inside the method; they never leak out as a return value.
/// </summary>
public interface ISshAuthenticationMethod
{
    /// <summary>Gets the RFC 4252 method name (e.g. <c>none</c>, <c>password</c>, <c>publickey</c>, <c>keyboard-interactive</c>).</summary>
    string MethodName { get; }

    /// <summary>
    /// Attempts authentication with this method.
    /// </summary>
    /// <param name="conversation">The dialog seam for sending requests and reading replies.</param>
    /// <param name="cancellationToken">Cancels the attempt.</param>
    /// <returns>The terminal reply — success or failure.</returns>
    /// <exception cref="SshAuthenticationException">The exchange was malformed or produced an unexpected message.</exception>
    ValueTask<SshAuthenticationReply> AttemptAsync(ISshAuthenticationConversation conversation, CancellationToken cancellationToken = default);
}
