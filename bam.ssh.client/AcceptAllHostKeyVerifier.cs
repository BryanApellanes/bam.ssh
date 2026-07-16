namespace Bam.Ssh.Client;

/// <summary>
/// A host-key verifier that trusts every key. This provides NO protection against man-in-the-middle
/// attacks and must only be used in tests or tightly controlled first-run scenarios — never as a default
/// in production. The name is deliberately blunt so its use is obvious in review.
/// </summary>
public sealed class AcceptAllHostKeyVerifier : ISshHostKeyVerifier
{
    /// <summary>
    /// The shared insecure instance.
    /// </summary>
    public static readonly AcceptAllHostKeyVerifier Instance = new AcceptAllHostKeyVerifier();

    /// <inheritdoc/>
    public ValueTask<bool> VerifyAsync(SshHostKeyVerificationContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        return ValueTask.FromResult(true);
    }
}
