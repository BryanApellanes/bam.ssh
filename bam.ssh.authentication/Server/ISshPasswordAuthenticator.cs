namespace Bam.Ssh.Authentication;

/// <summary>
/// A server-side policy that decides whether a user name and password are acceptable (RFC 4252 §8).
/// </summary>
public interface ISshPasswordAuthenticator
{
    /// <summary>
    /// Decides whether the given password authenticates the user.
    /// </summary>
    /// <param name="userName">The user name from the authentication request.</param>
    /// <param name="password">The offered password.</param>
    /// <param name="cancellationToken">Cancels the decision.</param>
    /// <returns>True to accept the credential.</returns>
    ValueTask<bool> AuthenticateAsync(string userName, string password, CancellationToken cancellationToken = default);
}
