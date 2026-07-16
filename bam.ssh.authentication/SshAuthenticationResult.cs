namespace Bam.Ssh.Authentication;

/// <summary>
/// The outcome of the whole authentication dialog: whether a method succeeded, which one, and — when
/// no method succeeded — the authentications the server said could still continue and whether partial
/// success was reached. An ordinary rejection is reported here (not thrown); only protocol-level
/// errors raise <see cref="SshAuthenticationException"/>.
/// </summary>
public sealed class SshAuthenticationResult
{
    /// <summary>
    /// Initializes an authentication result.
    /// </summary>
    /// <param name="succeeded">Whether authentication succeeded.</param>
    /// <param name="methodUsed">The method that succeeded, or null when none did.</param>
    /// <param name="methodsThatCanContinue">The authentications that can still continue after the last failure.</param>
    /// <param name="partialSuccess">Whether the last failure reported partial success.</param>
    public SshAuthenticationResult(
        bool succeeded,
        string? methodUsed,
        IReadOnlyList<string> methodsThatCanContinue,
        bool partialSuccess)
    {
        Succeeded = succeeded;
        MethodUsed = methodUsed;
        MethodsThatCanContinue = methodsThatCanContinue;
        PartialSuccess = partialSuccess;
    }

    /// <summary>Gets a value indicating whether authentication succeeded.</summary>
    public bool Succeeded { get; }

    /// <summary>Gets the name of the method that succeeded, or null when authentication failed.</summary>
    public string? MethodUsed { get; }

    /// <summary>Gets the authentications the server said could continue after the last failure.</summary>
    public IReadOnlyList<string> MethodsThatCanContinue { get; }

    /// <summary>Gets a value indicating whether the last failure reported partial success.</summary>
    public bool PartialSuccess { get; }
}
