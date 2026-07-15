using System.IO.Pipelines;
using System.Net.Sockets;

namespace Bam.Ssh.Transport;

/// <summary>
/// An <see cref="ISshDuplexStream"/> over a connected TCP socket. Wraps the socket's
/// <see cref="NetworkStream"/> in Pipelines readers and writers so the transport reads and writes
/// through back-pressured pipes. The only bam.ssh type that depends on <see cref="System.Net.Sockets"/>;
/// Unix-socket and custom transports are separate implementations of the same interface.
/// </summary>
public sealed class SshTcpDuplexStream : ISshDuplexStream
{
    private readonly Socket _socket;
    private readonly NetworkStream _networkStream;

    private SshTcpDuplexStream(Socket socket)
    {
        _socket = socket;
        _networkStream = new NetworkStream(socket, ownsSocket: false);
        Input = PipeReader.Create(_networkStream);
        Output = PipeWriter.Create(_networkStream);
    }

    /// <summary>
    /// Gets the reader delivering bytes received from the peer.
    /// </summary>
    public PipeReader Input { get; }

    /// <summary>
    /// Gets the writer accepting bytes to send to the peer.
    /// </summary>
    public PipeWriter Output { get; }

    /// <summary>
    /// Connects to a host and port and returns a duplex stream over the resulting socket, with
    /// Nagle's algorithm disabled so interactive traffic is not delayed.
    /// </summary>
    /// <param name="host">The DNS name or IP address to connect to.</param>
    /// <param name="port">The TCP port (SSH default 22).</param>
    /// <param name="cancellationToken">Cancels the connection attempt.</param>
    /// <returns>A connected duplex stream.</returns>
    public static async ValueTask<SshTcpDuplexStream> ConnectAsync(string host, int port, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(host);
        ArgumentOutOfRangeException.ThrowIfLessThan(port, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(port, 65535);

        Socket socket = new Socket(SocketType.Stream, ProtocolType.Tcp)
        {
            NoDelay = true
        };
        try
        {
            await socket.ConnectAsync(host, port, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
        return new SshTcpDuplexStream(socket);
    }

    /// <summary>
    /// Wraps an already-connected socket (used by the server for accepted connections).
    /// </summary>
    /// <param name="socket">A connected stream socket. The duplex stream takes ownership.</param>
    /// <returns>A duplex stream over the socket.</returns>
    public static SshTcpDuplexStream FromConnectedSocket(Socket socket)
    {
        ArgumentNullException.ThrowIfNull(socket);
        return new SshTcpDuplexStream(socket);
    }

    /// <summary>
    /// Completes both pipes and shuts the socket down gracefully.
    /// </summary>
    /// <param name="cancellationToken">Observed for cancellation; the socket is released regardless.</param>
    /// <returns>A task that completes when the transport is closed.</returns>
    public async ValueTask CloseAsync(CancellationToken cancellationToken = default)
    {
        await Input.CompleteAsync().ConfigureAwait(false);
        await Output.CompleteAsync().ConfigureAwait(false);
        try
        {
            _socket.Shutdown(SocketShutdown.Both);
        }
        catch (SocketException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
    }

    /// <summary>
    /// Releases the socket and its network stream.
    /// </summary>
    /// <returns>A task that completes when resources are released.</returns>
    public async ValueTask DisposeAsync()
    {
        await CloseAsync().ConfigureAwait(false);
        await _networkStream.DisposeAsync().ConfigureAwait(false);
        _socket.Dispose();
    }
}
