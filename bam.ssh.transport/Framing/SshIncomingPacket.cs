namespace Bam.Ssh.Transport;

/// <summary>
/// A decoded inbound SSH packet payload, owned by the caller. The reader copies the payload out of
/// the transport's pipe buffer into a pooled <see cref="SshRentedBuffer"/> (because the pipe memory
/// is only valid until the reader advances), then hands ownership here. The first payload byte is
/// the SSH message number. Dispose after parsing to return the buffer to the pool (zeroed).
/// </summary>
public struct SshIncomingPacket : IDisposable
{
    private SshRentedBuffer _buffer;
    private readonly int _length;

    /// <summary>
    /// Initializes an incoming packet over a rented buffer holding the payload.
    /// </summary>
    /// <param name="buffer">The pooled buffer holding exactly the payload bytes.</param>
    /// <param name="length">The payload length in bytes.</param>
    internal SshIncomingPacket(SshRentedBuffer buffer, int length)
    {
        _buffer = buffer;
        _length = length;
    }

    /// <summary>
    /// Gets the payload length in bytes (including the leading message-number byte).
    /// </summary>
    public readonly int Length => _length;

    /// <summary>
    /// Gets whether the payload is empty (no message number — a protocol error at higher layers).
    /// </summary>
    public readonly bool IsEmpty => _length == 0;

    /// <summary>
    /// Gets the SSH message number (the first payload byte).
    /// </summary>
    /// <exception cref="InvalidOperationException">The payload is empty.</exception>
    public readonly byte MessageNumber
    {
        get
        {
            if (_length == 0)
            {
                throw new InvalidOperationException("The packet payload is empty and has no message number.");
            }
            return _buffer.Span[0];
        }
    }

    /// <summary>
    /// Gets the full payload including the message-number byte.
    /// </summary>
    public readonly ReadOnlySpan<byte> Payload => _buffer.Span.Slice(0, _length);

    /// <summary>
    /// Gets the payload after the message-number byte — the message-specific fields.
    /// </summary>
    public readonly ReadOnlySpan<byte> Body => _length == 0 ? ReadOnlySpan<byte>.Empty : _buffer.Span.Slice(1, _length - 1);

    /// <summary>
    /// Returns the pooled buffer (zeroed) to the pool. Safe to call more than once.
    /// </summary>
    public void Dispose()
    {
        _buffer.Dispose();
    }
}
