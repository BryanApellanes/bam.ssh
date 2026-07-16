namespace Bam.Ssh.Authentication;

/// <summary>
/// A server-side policy that decides whether a user is authorized to authenticate with a given public
/// key (RFC 4252 §7) — the equivalent of consulting <c>authorized_keys</c>. The
/// <see cref="SshServerAuthenticator"/> separately verifies the request's signature with the production
/// transport verifier, so this policy only decides <em>authorization</em>, not signature validity.
/// </summary>
public interface ISshPublicKeyAuthenticator
{
    /// <summary>
    /// Decides whether the user is authorized to use the given public key.
    /// </summary>
    /// <param name="userName">The user name from the authentication request.</param>
    /// <param name="algorithm">The public-key algorithm name.</param>
    /// <param name="publicKeyBlob">The offered public-key blob.</param>
    /// <param name="cancellationToken">Cancels the decision.</param>
    /// <returns>True if the key is authorized for the user.</returns>
    ValueTask<bool> IsAuthorizedAsync(string userName, string algorithm, ReadOnlyMemory<byte> publicKeyBlob, CancellationToken cancellationToken = default);
}
