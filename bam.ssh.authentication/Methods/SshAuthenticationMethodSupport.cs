namespace Bam.Ssh.Authentication;

/// <summary>
/// Shared guards for authentication methods.
/// </summary>
internal static class SshAuthenticationMethodSupport
{
    /// <summary>
    /// Verifies a reply is terminal (success or failure) and returns it, throwing when a method
    /// received an unexpected method-specific message it does not understand.
    /// </summary>
    /// <param name="reply">The reply to validate.</param>
    /// <param name="methodName">The method name, for the error message.</param>
    /// <returns>The reply, when it is terminal.</returns>
    /// <exception cref="SshAuthenticationException">The reply was an unexpected method-specific message.</exception>
    public static SshAuthenticationReply EnsureTerminal(SshAuthenticationReply reply, string methodName)
    {
        if (reply.Kind == SshAuthenticationReplyKind.MethodSpecific)
        {
            throw new SshAuthenticationException(
                $"The '{methodName}' method received an unexpected method-specific message {reply.MessageNumber}.");
        }
        return reply;
    }
}
