namespace Bam.Ssh.Connection;

/// <summary>
/// The inbound half of a channel's flow control: how many bytes the peer may still send this side
/// before it must wait for a WINDOW_ADJUST (RFC 4254 §5.2). The window shrinks as data arrives
/// (<see cref="RecordReceived"/>) and is replenished only as the local consumer actually drains the
/// buffered data (<see cref="RecordConsumed"/>), which is what prevents a slow channel from
/// head-of-line-blocking the shared transport. Thread-safe.
/// </summary>
internal sealed class SshReceiveWindow
{
    private readonly object _gate = new object();
    private readonly int _initial;
    private readonly long _replenishThreshold;
    private long _remaining;
    private long _freed;

    /// <summary>
    /// Initializes the window at its advertised initial size.
    /// </summary>
    /// <param name="initial">The initial window advertised to the peer.</param>
    public SshReceiveWindow(int initial)
    {
        _initial = initial;
        _remaining = initial;
        _replenishThreshold = Math.Max(1, initial / 2);
    }

    /// <summary>
    /// Records bytes just received from the peer, shrinking the window.
    /// </summary>
    /// <param name="count">The number of payload bytes received.</param>
    /// <exception cref="SshChannelException">The peer sent more than the advertised window allowed.</exception>
    public void RecordReceived(int count)
    {
        lock (_gate)
        {
            _remaining -= count;
            if (_remaining < 0)
            {
                throw new SshChannelException("The peer sent more channel data than its window allowed.");
            }
        }
    }

    /// <summary>
    /// Records bytes the local consumer has drained. When enough has been freed (at least half the
    /// initial window) it returns a positive increment to advertise back to the peer in a
    /// WINDOW_ADJUST; otherwise it returns zero to amortize adjust traffic.
    /// </summary>
    /// <param name="count">The number of bytes the consumer read out.</param>
    /// <returns>The WINDOW_ADJUST increment to send, or zero if none is due yet.</returns>
    public uint RecordConsumed(int count)
    {
        lock (_gate)
        {
            _freed += count;
            if (_freed >= _replenishThreshold)
            {
                uint increment = (uint)_freed;
                _remaining += _freed;
                _freed = 0;
                return increment;
            }
            return 0;
        }
    }
}
