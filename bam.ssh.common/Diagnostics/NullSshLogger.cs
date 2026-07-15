namespace Bam.Ssh;

/// <summary>
/// An <see cref="ISshLogger"/> that discards every message. The default logger wherever a host
/// supplies none, so logging calls never need null checks. Reports every level as disabled so
/// callers short-circuit argument construction.
/// </summary>
public sealed class NullSshLogger : ISshLogger
{
    /// <summary>
    /// Gets the shared no-op logger instance.
    /// </summary>
    public static NullSshLogger Instance { get; } = new NullSshLogger();

    /// <summary>
    /// Always returns false — the null logger records nothing.
    /// </summary>
    /// <param name="level">Ignored.</param>
    /// <returns>False.</returns>
    public bool IsEnabled(SshLogLevel level)
    {
        return false;
    }

    /// <summary>
    /// Discards the message.
    /// </summary>
    /// <param name="level">Ignored.</param>
    /// <param name="messageTemplate">Ignored.</param>
    /// <param name="arguments">Ignored.</param>
    public void Log(SshLogLevel level, string messageTemplate, params object?[] arguments)
    {
    }
}
