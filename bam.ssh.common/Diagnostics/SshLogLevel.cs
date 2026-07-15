namespace Bam.Ssh;

/// <summary>
/// Severity levels for <see cref="ISshLogger"/>, ordered from most to least verbose.
/// Kept deliberately minimal and framework-agnostic so the core libraries carry no logging
/// dependency; an adapter maps these onto a host logging framework in the client/server layers.
/// </summary>
public enum SshLogLevel
{
    /// <summary>Fine-grained protocol tracing (packet-level events, sequence numbers).</summary>
    Trace = 0,

    /// <summary>Diagnostic information useful when debugging a connection.</summary>
    Debug = 1,

    /// <summary>Normal lifecycle events (connected, authenticated, channel opened).</summary>
    Information = 2,

    /// <summary>A recoverable anomaly that did not abort the connection.</summary>
    Warning = 3,

    /// <summary>A failure that aborted an operation or the connection.</summary>
    Error = 4
}
