using System.Threading.Channels;

namespace Bam.Ssh.Transport;

/// <summary>
/// A single-producer, single-consumer queue of decoded packets used to feed a loop-driven re-key.
/// The connection's receive-dispatch loop is the sole reader of the transport; when it detects a
/// key-exchange packet during a re-key it copies the payload into this queue via <see cref="Write"/>,
/// and the key-exchange routine consumes packets through the <see cref="ISshPacketSource"/> seam. The
/// payload is copied into a pooled buffer because the loop's source packet is disposed once forwarded.
/// </summary>
public sealed class SshPacketQueue : ISshPacketSource
{
    private readonly Channel<SshIncomingPacket> _channel;

    /// <summary>
    /// Initializes an empty queue.
    /// </summary>
    public SshPacketQueue()
    {
        _channel = System.Threading.Channels.Channel.CreateUnbounded<SshIncomingPacket>(
            new UnboundedChannelOptions { SingleReader = true, SingleWriter = true });
    }

    /// <summary>
    /// Copies a packet payload into the queue for later consumption.
    /// </summary>
    /// <param name="payload">The full packet payload, including the leading message-number byte.</param>
    public void Write(ReadOnlySpan<byte> payload)
    {
        SshRentedBuffer buffer = SshRentedBuffer.Rent(payload.Length);
        payload.CopyTo(buffer.Span);
        SshIncomingPacket packet = new SshIncomingPacket(buffer, payload.Length);
        if (!_channel.Writer.TryWrite(packet))
        {
            packet.Dispose();
            throw new InvalidOperationException("The packet queue rejected a write after completion.");
        }
    }

    /// <summary>
    /// Marks the queue complete; a pending or subsequent receive throws once the queue drains.
    /// </summary>
    public void Complete()
    {
        _channel.Writer.TryComplete();
    }

    /// <inheritdoc/>
    public async ValueTask<SshIncomingPacket> ReceivePacketAsync(CancellationToken cancellationToken = default)
    {
        return await _channel.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
    }
}
