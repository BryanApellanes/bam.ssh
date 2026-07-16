namespace Bam.Ssh.Connection;

/// <summary>
/// The outbound half of a channel's flow control: the number of bytes the peer has authorized this
/// side to send (RFC 4254 §5.2). A writer calls <see cref="ReserveAsync"/> to claim send capacity,
/// asynchronously waiting when the window is exhausted; the peer's SSH_MSG_CHANNEL_WINDOW_ADJUST
/// messages replenish it through <see cref="Adjust"/>. Thread-safe.
/// </summary>
internal sealed class SshSendWindow
{
    private const long MaximumWindow = uint.MaxValue;

    private readonly object _gate = new object();
    private long _remaining;
    private bool _closed;
    private TaskCompletionSource _signal = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>
    /// Initializes the window with the peer's initial advertised size.
    /// </summary>
    /// <param name="initial">The initial number of bytes this side may send.</param>
    public SshSendWindow(long initial)
    {
        _remaining = initial;
    }

    /// <summary>
    /// Increases the window by an increment received in a WINDOW_ADJUST message and wakes any waiters.
    /// </summary>
    /// <param name="increment">The number of additional bytes now permitted.</param>
    /// <exception cref="SshChannelException">The increment would grow the window beyond 2^32-1.</exception>
    public void Adjust(uint increment)
    {
        lock (_gate)
        {
            _remaining += increment;
            if (_remaining > MaximumWindow)
            {
                throw new SshChannelException("The peer grew the channel window beyond the protocol maximum.");
            }
            Signal();
        }
    }

    /// <summary>
    /// Permanently closes the window; pending and future reservations fault.
    /// </summary>
    public void Close()
    {
        lock (_gate)
        {
            _closed = true;
            Signal();
        }
    }

    /// <summary>
    /// Reserves up to <paramref name="maxWanted"/> bytes of send capacity, waiting until at least one
    /// byte is available. Returns the granted count (at least one), which the caller then sends.
    /// </summary>
    /// <param name="maxWanted">The most bytes the caller wants to send next.</param>
    /// <param name="cancellationToken">Cancels the wait.</param>
    /// <returns>The number of bytes granted (1..<paramref name="maxWanted"/>).</returns>
    /// <exception cref="SshChannelException">The channel closed while waiting.</exception>
    public async ValueTask<int> ReserveAsync(int maxWanted, CancellationToken cancellationToken)
    {
        while (true)
        {
            Task wait;
            lock (_gate)
            {
                if (_closed)
                {
                    throw new SshChannelException("The channel was closed while waiting to send.");
                }
                if (_remaining > 0)
                {
                    int grant = (int)Math.Min(maxWanted, _remaining);
                    _remaining -= grant;
                    return grant;
                }
                wait = _signal.Task;
            }
            await wait.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private void Signal()
    {
        TaskCompletionSource previous = _signal;
        _signal = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        previous.TrySetResult();
    }
}
