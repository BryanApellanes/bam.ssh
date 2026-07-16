using Bam.Ssh.Connection;
using Bam.Ssh.Transport;

namespace Bam.Ssh.Client;

/// <summary>
/// Periodically sends a <c>keepalive@openssh.com</c> global request over the connection so idle sessions
/// are not dropped by intermediaries and a dead peer is detected. Per OpenSSH convention the request sets
/// <c>want_reply</c>, and <em>either</em> a success or a failure reply proves the peer is alive — only the
/// absence of a reply (a fault) indicates a dead connection. Runs until stopped or the connection faults.
/// </summary>
internal sealed class SshClientKeepAlive : IAsyncDisposable
{
    private const string KeepAliveRequest = "keepalive@openssh.com";

    private readonly SshConnection _connection;
    private readonly TimeSpan _interval;
    private readonly ISshLogger _logger;
    private readonly CancellationTokenSource _stop = new CancellationTokenSource();
    private Task _loop = Task.CompletedTask;

    public SshClientKeepAlive(SshConnection connection, TimeSpan interval, ISshLogger logger)
    {
        _connection = connection;
        _interval = interval;
        _logger = logger;
    }

    public void Start()
    {
        _loop = RunAsync(_stop.Token);
    }

    private async Task RunAsync(CancellationToken cancellationToken)
    {
        try
        {
            using PeriodicTimer timer = new PeriodicTimer(_interval);
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
            {
                // A success or a failure reply both prove liveness; only a fault (no reply) matters.
                await _connection.SendGlobalRequestAsync(KeepAliveRequest, wantReply: true, ReadOnlyMemory<byte>.Empty, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // Stopped.
        }
        catch (SshException exception)
        {
            if (_logger.IsEnabled(SshLogLevel.Warning))
            {
                _logger.Log(SshLogLevel.Warning, "Keep-alive stopped: {0}", exception.Message);
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        _stop.Cancel();
        try
        {
            await _loop.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Expected on stop.
        }
        _stop.Dispose();
    }
}
