namespace Bam.Ssh;

/// <summary>
/// A minimal structured-logging seam every bam.ssh layer can emit to without taking a dependency
/// on any logging framework (which would break the Native AOT / zero-external-dependency contract
/// of the core libraries). Hosts adapt this onto their own logger in the client/server composition
/// roots. Implementations must be safe for concurrent use.
/// </summary>
public interface ISshLogger
{
    /// <summary>
    /// Determines whether messages at the given level would be recorded, so callers can skip
    /// building expensive message arguments when logging is disabled.
    /// </summary>
    /// <param name="level">The level to test.</param>
    /// <returns>True when a message at this level would be emitted.</returns>
    bool IsEnabled(SshLogLevel level);

    /// <summary>
    /// Records a message. <paramref name="messageTemplate"/> uses positional <c>{0}</c>-style
    /// placeholders filled from <paramref name="arguments"/>; implementations may treat the
    /// template and arguments structurally rather than formatting eagerly.
    /// </summary>
    /// <param name="level">The severity level.</param>
    /// <param name="messageTemplate">The message template with positional placeholders.</param>
    /// <param name="arguments">The values for the template placeholders.</param>
    void Log(SshLogLevel level, string messageTemplate, params object?[] arguments);
}
