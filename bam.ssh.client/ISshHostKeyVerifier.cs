namespace Bam.Ssh.Client;

/// <summary>
/// Decides whether a server's host key should be trusted (RFC 4251 §4.1). The key exchange only proves
/// a host-key signature is cryptographically valid; this seam makes the <em>trust</em> decision — for
/// example against an OpenSSH <c>known_hosts</c> file, a first-use (TOFU) policy, or an interactive
/// callback. Called after key exchange and before any credentials are sent; returning false aborts the
/// connection with an <see cref="SshHostKeyRejectedException"/>.
/// </summary>
public interface ISshHostKeyVerifier
{
    /// <summary>
    /// Decides whether the host key in <paramref name="context"/> is trusted.
    /// </summary>
    /// <param name="context">The host, port, and verified host key.</param>
    /// <param name="cancellationToken">Cancels the decision (e.g. an interactive prompt).</param>
    /// <returns>True to trust the key and continue; false to reject and abort.</returns>
    ValueTask<bool> VerifyAsync(SshHostKeyVerificationContext context, CancellationToken cancellationToken = default);
}
