using System.Buffers;
using System.Net.Sockets;
using Bam.Ssh.Connection;

namespace Bam.Ssh.Forwarding;

/// <summary>
/// Copies bytes in both directions between a TCP <see cref="Socket"/> and an <see cref="SshChannel"/> until
/// each direction ends, then tears both down. Socket EOF becomes a channel EOF (and vice versa) so a
/// half-closed connection is honored. Every pump is fault-contained: a broken tunnel closes only its own
/// socket and channel and never faults the shared <see cref="SshConnection"/>.
/// </summary>
public static class SshChannelSocketBridge
{
    private const int BufferSize = 32 * 1024;

    /// <summary>
    /// Runs both pump directions to completion, then closes the channel and disposes the socket.
    /// </summary>
    /// <param name="socket">The TCP socket end of the tunnel. Disposed on completion.</param>
    /// <param name="channel">The SSH channel end of the tunnel. Closed on completion.</param>
    /// <param name="cancellationToken">Tears the tunnel down.</param>
    /// <exception cref="ArgumentNullException">The socket or channel is null.</exception>
    public static async Task RunAsync(Socket socket, SshChannel channel, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(socket);
        ArgumentNullException.ThrowIfNull(channel);

        Task socketToChannel = PumpSocketToChannelAsync(socket, channel, cancellationToken);
        Task channelToSocket = PumpChannelToSocketAsync(channel, socket, cancellationToken);
        await Task.WhenAll(socketToChannel, channelToSocket).ConfigureAwait(false);

        try
        {
            await channel.CloseAsync(CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // The channel may already be closed or the connection gone; teardown is best-effort.
        }
        try
        {
            socket.Dispose();
        }
        catch (Exception)
        {
            // Best-effort.
        }
    }

    private static async Task PumpSocketToChannelAsync(Socket socket, SshChannel channel, CancellationToken cancellationToken)
    {
        byte[] buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
        try
        {
            while (true)
            {
                int read = await socket.ReceiveAsync(buffer.AsMemory(0, BufferSize), SocketFlags.None, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    await channel.SendEofAsync(cancellationToken).ConfigureAwait(false);
                    return;
                }
                await channel.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            }
        }
        catch (Exception)
        {
            // Isolate the tunnel: a read/write failure ends this direction; RunAsync still tears down.
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static async Task PumpChannelToSocketAsync(SshChannel channel, Socket socket, CancellationToken cancellationToken)
    {
        byte[] buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
        try
        {
            while (true)
            {
                int read = await channel.ReadAsync(buffer.AsMemory(0, BufferSize), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    try
                    {
                        socket.Shutdown(SocketShutdown.Send);
                    }
                    catch (Exception)
                    {
                        // The socket may already be closed.
                    }
                    return;
                }
                await SendAllAsync(socket, buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            }
        }
        catch (Exception)
        {
            // Isolate the tunnel.
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static async ValueTask SendAllAsync(Socket socket, ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
    {
        int sent = 0;
        while (sent < data.Length)
        {
            int count = await socket.SendAsync(data.Slice(sent), SocketFlags.None, cancellationToken).ConfigureAwait(false);
            if (count == 0)
            {
                throw new SshForwardingException("The socket send returned zero — the peer closed the connection.");
            }
            sent += count;
        }
    }
}
