namespace Bam.Ssh.Client;

/// <summary>
/// Thrown when the configured <see cref="ISshHostKeyVerifier"/> refuses the server's host key — the key
/// is unknown under a strict policy, or (more seriously) it differs from a previously trusted key for the
/// same host, which may indicate a man-in-the-middle attack. The connection is torn down before any
/// credentials are sent.
/// </summary>
public sealed class SshHostKeyRejectedException : SshException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="SshHostKeyRejectedException"/> class.
    /// </summary>
    /// <param name="host">The host whose key was rejected.</param>
    /// <param name="fingerprint">The rejected key's fingerprint.</param>
    public SshHostKeyRejectedException(string host, string fingerprint)
        : base($"The host key for '{host}' ({fingerprint}) was rejected by the host-key verifier.")
    {
        Host = host;
        Fingerprint = fingerprint;
    }

    /// <summary>
    /// Gets the host whose key was rejected.
    /// </summary>
    public string Host { get; }

    /// <summary>
    /// Gets the rejected key's fingerprint.
    /// </summary>
    public string Fingerprint { get; }
}
