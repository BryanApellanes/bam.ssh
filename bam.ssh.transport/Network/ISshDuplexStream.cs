using System.IO.Pipelines;

namespace Bam.Ssh.Transport;

/// <summary>
/// Abstracts the full-duplex byte transport beneath SSH as a System.IO.Pipelines reader/writer
/// pair, so the protocol stack is agnostic to whether bytes travel over TCP, a Unix domain socket,
/// or a custom channel. This is the lowest seam in the layering — the only place that knows about
/// the concrete network resource. Implementations own the underlying resource and release it on
/// <see cref="CloseAsync"/>.
/// </summary>
public interface ISshDuplexStream : IAsyncDisposable
{
    /// <summary>
    /// Gets the reader delivering bytes received from the peer.
    /// </summary>
    PipeReader Input { get; }

    /// <summary>
    /// Gets the writer accepting bytes to send to the peer.
    /// </summary>
    PipeWriter Output { get; }

    /// <summary>
    /// Completes both directions and releases the underlying transport resource. Idempotent.
    /// </summary>
    /// <param name="cancellationToken">Cancels a graceful shutdown; the resource is still released.</param>
    /// <returns>A task that completes when the transport is closed.</returns>
    ValueTask CloseAsync(CancellationToken cancellationToken = default);
}
