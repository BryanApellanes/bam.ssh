using System.Diagnostics;

namespace Bam.Ssh;

/// <summary>
/// Holds the process-wide <see cref="ActivitySource"/> bam.ssh uses to emit distributed-tracing
/// spans (connection, version exchange, key exchange, packet send/receive). Consumers subscribe
/// with an <see cref="ActivityListener"/> or OpenTelemetry; when no listener is attached,
/// starting an activity returns null and costs nothing.
/// </summary>
public static class SshActivitySource
{
    /// <summary>
    /// The activity source name to subscribe to (<c>Bam.Ssh</c>).
    /// </summary>
    public const string Name = "Bam.Ssh";

    /// <summary>
    /// Gets the shared activity source. Use <c>Instance.StartActivity(...)</c> to begin a span;
    /// guard nothing — a null return simply means no listener is attached.
    /// </summary>
    public static ActivitySource Instance { get; } = new ActivitySource(Name);
}
