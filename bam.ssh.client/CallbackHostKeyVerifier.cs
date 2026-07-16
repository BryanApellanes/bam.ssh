namespace Bam.Ssh.Client;

/// <summary>
/// A host-key verifier that delegates the trust decision to a caller-supplied callback — for example an
/// interactive prompt ("The authenticity of host X can't be established … continue?") or an enterprise
/// policy lookup.
/// </summary>
public sealed class CallbackHostKeyVerifier : ISshHostKeyVerifier
{
    private readonly Func<SshHostKeyVerificationContext, CancellationToken, ValueTask<bool>> _callback;

    /// <summary>
    /// Initializes the verifier with the decision callback.
    /// </summary>
    /// <param name="callback">Returns true to trust the key, false to reject it.</param>
    /// <exception cref="ArgumentNullException">The callback is null.</exception>
    public CallbackHostKeyVerifier(Func<SshHostKeyVerificationContext, CancellationToken, ValueTask<bool>> callback)
    {
        ArgumentNullException.ThrowIfNull(callback);
        _callback = callback;
    }

    /// <inheritdoc/>
    public ValueTask<bool> VerifyAsync(SshHostKeyVerificationContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        return _callback(context, cancellationToken);
    }
}
