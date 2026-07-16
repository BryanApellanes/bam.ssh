using Bam.Ssh.Client;
using Bam.Ssh.Transport;

namespace Bam.Ssh.Tests.Unit;

/// <summary>
/// Drives a full <see cref="SshClient"/> against a combined server that chains the proven Phase 3/5/6
/// test doubles — version exchange, <see cref="TestServerKeyExchange"/>, <see cref="TestUserAuthServer"/>,
/// then <see cref="TestConnectionServer"/> — over one loopback transport, so a single client call sequence
/// (connect → authenticate → execute) exercises the whole stack end to end. The server is cancelled on
/// teardown so a client that stops mid-dialog cannot hang it.
/// </summary>
internal static class ClientTestSupport
{
    public static T Run<T>(
        SshClientOptions clientOptions,
        TestUserAuthServer authServer,
        TestConnectionServer connectionServer,
        Func<SshClient, ISshDuplexStream, Task<T>> body)
    {
        (LoopbackDuplexStream clientStream, LoopbackDuplexStream serverStream) = LoopbackDuplexStream.CreatePair();
        CombinedTestServer server = new CombinedTestServer(serverStream, authServer, connectionServer);
        CancellationTokenSource serverCancellation = new CancellationTokenSource();
        Task serverTask = server.RunAsync(serverCancellation.Token);
        SshClient client = new SshClient(clientOptions);
        try
        {
            return body(client, clientStream).GetAwaiter().GetResult();
        }
        finally
        {
            serverCancellation.Cancel();
            try
            {
                serverTask.GetAwaiter().GetResult();
            }
            catch (Exception)
            {
                // Best-effort teardown; a cancelled mid-receive server must not mask the client result.
            }
            client.DisposeAsync().AsTask().GetAwaiter().GetResult();
            serverCancellation.Dispose();
        }
    }
}

/// <summary>
/// Plays the server side of a full client session by running the existing phase doubles in sequence over
/// one keyed transport: version exchange, key exchange (which generates a host key and activates ciphers),
/// user authentication, then the connection/channel loop.
/// </summary>
internal sealed class CombinedTestServer
{
    private readonly LoopbackDuplexStream _stream;
    private readonly TestUserAuthServer _authServer;
    private readonly TestConnectionServer _connectionServer;

    public CombinedTestServer(LoopbackDuplexStream stream, TestUserAuthServer authServer, TestConnectionServer connectionServer)
    {
        _stream = stream;
        _authServer = authServer;
        _connectionServer = connectionServer;
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        SshTransport transport = new SshTransport(_stream, new SshTransportOptions("Bam.Ssh_TestServer"));
        try
        {
            await transport.ConnectAsync(cancellationToken).ConfigureAwait(false);

            (byte[] hostKeyBlob, Func<byte[], byte[]> sign) = TestHostKeys.CreateEd25519();
            TestServerKeyExchange serverKex = new TestServerKeyExchange(transport, hostKeyBlob, sign);
            await serverKex.RunAsync(null, cancellationToken).ConfigureAwait(false);
            byte[] sessionId = serverKex.SessionKeys!.SessionId;

            _authServer.SessionId = sessionId;
            await _authServer.RunAsync(transport, cancellationToken).ConfigureAwait(false);

            _connectionServer.Attach(transport, sessionId);
            await _connectionServer.RunAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Shutdown.
        }
        finally
        {
            await transport.DisposeAsync().ConfigureAwait(false);
        }
    }
}
