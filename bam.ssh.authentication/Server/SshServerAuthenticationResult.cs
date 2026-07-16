namespace Bam.Ssh.Authentication;

/// <summary>
/// The outcome of a successful server-side authentication: who authenticated and by which method.
/// </summary>
public sealed class SshServerAuthenticationResult
{
    /// <summary>
    /// Initializes the result.
    /// </summary>
    /// <param name="userName">The authenticated user name.</param>
    /// <param name="methodUsed">The method that succeeded (e.g. <c>password</c>, <c>publickey</c>).</param>
    /// <exception cref="ArgumentNullException">The user name or method is null.</exception>
    public SshServerAuthenticationResult(string userName, string methodUsed)
    {
        ArgumentNullException.ThrowIfNull(userName);
        ArgumentNullException.ThrowIfNull(methodUsed);
        UserName = userName;
        MethodUsed = methodUsed;
    }

    /// <summary>
    /// Gets the authenticated user name.
    /// </summary>
    public string UserName { get; }

    /// <summary>
    /// Gets the method that succeeded.
    /// </summary>
    public string MethodUsed { get; }
}
