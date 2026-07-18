using System.Net;
using System.Net.Sockets;
using System.Text;
using Bam.Ssh.Authentication;
using Bam.Ssh.Forwarding;
using Bam.Ssh.Server;
using Bam.Test;

namespace Bam.Ssh.Tests.Unit;

/// <summary>
/// The crown-jewel Phase 11 tests: over the production <see cref="Bam.Ssh.Client.SshClient"/> ↔
/// <see cref="SshServer"/> loopback (with <c>EnableTcpForwarding</c>) and real TCP loopback echo targets, a
/// local (<c>-L</c>), a remote (<c>-R</c>), and a dynamic SOCKS (<c>-D</c>) forward each tunnel bytes to the
/// echo target and back.
/// </summary>
[UnitTestMenu("PortForwardingShould", Selector = "forwarding")]
public class PortForwardingShould : UnitTestMenuContainer
{
    [UnitTest]
    public void ForwardALocalPortToARemoteTarget()
    {
        When.A<object>("tunnels bytes through a local (-L) forward to a remote echo target", new object(), (ignored) =>
        {
            LoopbackEchoServer echo = new LoopbackEchoServer();
            try
            {
                return ServerTestSupport.Run(ConfigureForwardingServer, async (client, stream) =>
                {
                    await client.ConnectAsync(stream, "test-host", 22);
                    await client.AuthenticateWithPasswordAsync("tester", "s3cret");
                    await using LocalPortForwarder forwarder = await client.ForwardLocalPortAsync(0, "127.0.0.1", echo.Port);
                    return await RoundTripAsync(forwarder.ListenEndPoint!, "hello through the -L tunnel");
                });
            }
            finally
            {
                echo.DisposeAsync().AsTask().GetAwaiter().GetResult();
            }
        })
        .TheTest
        .ShouldPass(because => because.ItsTrue("the echo returned the bytes sent through the local forward", (string)because.Result == "hello through the -L tunnel"))
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void ForwardARemotePortToALocalTarget()
    {
        When.A<object>("tunnels bytes through a remote (-R) forward to a local echo target", new object(), (ignored) =>
        {
            LoopbackEchoServer echo = new LoopbackEchoServer();
            try
            {
                return ServerTestSupport.Run(ConfigureForwardingServer, async (client, stream) =>
                {
                    await client.ConnectAsync(stream, "test-host", 22);
                    await client.AuthenticateWithPasswordAsync("tester", "s3cret");
                    await using RemotePortForwarder forwarder = await client.ForwardRemotePortAsync(0, "127.0.0.1", echo.Port);
                    IPEndPoint serverBound = new IPEndPoint(IPAddress.Loopback, forwarder.BoundPort);
                    return await RoundTripAsync(serverBound, "hello through the -R tunnel");
                });
            }
            finally
            {
                echo.DisposeAsync().AsTask().GetAwaiter().GetResult();
            }
        })
        .TheTest
        .ShouldPass(because => because.ItsTrue("the echo returned the bytes sent through the remote forward", (string)because.Result == "hello through the -R tunnel"))
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void ForwardDynamicallyThroughSocks()
    {
        When.A<object>("tunnels bytes through a dynamic (-D) SOCKS5 forward to a target", new object(), (ignored) =>
        {
            LoopbackEchoServer echo = new LoopbackEchoServer();
            try
            {
                return ServerTestSupport.Run(ConfigureForwardingServer, async (client, stream) =>
                {
                    await client.ConnectAsync(stream, "test-host", 22);
                    await client.AuthenticateWithPasswordAsync("tester", "s3cret");
                    await using DynamicPortForwarder forwarder = await client.ForwardDynamicPortAsync(0);
                    return await Socks5RoundTripAsync(forwarder.ListenEndPoint!, "127.0.0.1", echo.Port, "hello through the -D tunnel");
                });
            }
            finally
            {
                echo.DisposeAsync().AsTask().GetAwaiter().GetResult();
            }
        })
        .TheTest
        .ShouldPass(because => because.ItsTrue("the echo returned the bytes sent through the SOCKS5 forward", (string)because.Result == "hello through the -D tunnel"))
        .SoBeHappy()
        .UnlessItFailed();
    }

    private static void ConfigureForwardingServer(SshServer server)
    {
        server.AddHostKey(new Ed25519PrivateKey(ServerTestSupport.MakeSeed(0x11)));
        server.UsePasswordAuthentication(new FixedPasswordAuthenticator("tester", "s3cret"));
        server.EnableTcpForwarding();
    }

    private static async Task<string> RoundTripAsync(IPEndPoint target, string message)
    {
        byte[] payload = Encoding.UTF8.GetBytes(message);
        using Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync(target);
        await SendAllAsync(socket, payload);
        byte[] response = await ReadExactAsync(socket, payload.Length);
        return Encoding.UTF8.GetString(response);
    }

    private static async Task<string> Socks5RoundTripAsync(IPEndPoint proxy, string targetHost, int targetPort, string message)
    {
        using Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync(proxy);
        await SendAllAsync(socket, new byte[] { 0x05, 0x01, 0x00 });
        byte[] methodReply = await ReadExactAsync(socket, 2);
        if (methodReply[1] != 0x00)
        {
            throw new InvalidOperationException("The SOCKS5 proxy did not select no-authentication.");
        }

        byte[] ipBytes = IPAddress.Parse(targetHost).GetAddressBytes();
        byte[] request = new byte[]
        {
            0x05, 0x01, 0x00, 0x01, ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3],
            (byte)(targetPort >> 8), (byte)(targetPort & 0xFF),
        };
        await SendAllAsync(socket, request);
        byte[] connectReply = await ReadExactAsync(socket, 10);
        if (connectReply[1] != 0x00)
        {
            throw new InvalidOperationException("The SOCKS5 CONNECT was refused.");
        }

        byte[] payload = Encoding.UTF8.GetBytes(message);
        await SendAllAsync(socket, payload);
        byte[] response = await ReadExactAsync(socket, payload.Length);
        return Encoding.UTF8.GetString(response);
    }

    private static async Task SendAllAsync(Socket socket, byte[] data)
    {
        int sent = 0;
        while (sent < data.Length)
        {
            sent += await socket.SendAsync(new ReadOnlyMemory<byte>(data, sent, data.Length - sent), SocketFlags.None);
        }
    }

    private static async Task<byte[]> ReadExactAsync(Socket socket, int count)
    {
        byte[] buffer = new byte[count];
        int offset = 0;
        while (offset < count)
        {
            int read = await socket.ReceiveAsync(new Memory<byte>(buffer, offset, count - offset), SocketFlags.None);
            if (read == 0)
            {
                throw new InvalidOperationException("The tunnel closed before the expected bytes arrived.");
            }
            offset += read;
        }
        return buffer;
    }

    /// <summary>
    /// A minimal TCP echo server on an ephemeral loopback port: every accepted connection is echoed back
    /// byte-for-byte until the peer half-closes. Used as the forwarding target on either side of a tunnel.
    /// </summary>
    private sealed class LoopbackEchoServer : IAsyncDisposable
    {
        private readonly Socket _listener;
        private readonly CancellationTokenSource _cancellation = new CancellationTokenSource();
        private readonly Task _acceptLoop;

        public LoopbackEchoServer()
        {
            _listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            _listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            _listener.Listen(16);
            Port = ((IPEndPoint)_listener.LocalEndPoint!).Port;
            _acceptLoop = AcceptLoopAsync(_cancellation.Token);
        }

        public int Port { get; }

        private async Task AcceptLoopAsync(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                Socket socket;
                try
                {
                    socket = await _listener.AcceptAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (Exception)
                {
                    break;
                }
                _ = EchoAsync(socket, cancellationToken);
            }
        }

        private static async Task EchoAsync(Socket socket, CancellationToken cancellationToken)
        {
            byte[] buffer = new byte[4096];
            try
            {
                while (true)
                {
                    int read = await socket.ReceiveAsync(buffer, SocketFlags.None, cancellationToken).ConfigureAwait(false);
                    if (read == 0)
                    {
                        break;
                    }
                    int sent = 0;
                    while (sent < read)
                    {
                        sent += await socket.SendAsync(new ReadOnlyMemory<byte>(buffer, sent, read - sent), SocketFlags.None, cancellationToken).ConfigureAwait(false);
                    }
                }
            }
            catch (Exception)
            {
                // The tunnel closed; nothing to do.
            }
            finally
            {
                try
                {
                    socket.Shutdown(SocketShutdown.Both);
                }
                catch (Exception)
                {
                    // Best-effort.
                }
                socket.Dispose();
            }
        }

        public async ValueTask DisposeAsync()
        {
            _cancellation.Cancel();
            _listener.Dispose();
            try
            {
                await _acceptLoop.ConfigureAwait(false);
            }
            catch (Exception)
            {
                // Best-effort drain.
            }
            _cancellation.Dispose();
        }
    }
}
