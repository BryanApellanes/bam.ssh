using Bam.Ssh.Transport;
using Bam.Test;

namespace Bam.Ssh.Tests.Unit;

[UnitTestMenu("SshClientKeyExchangeShould", Selector = "ckx")]
public class SshClientKeyExchangeShould : UnitTestMenuContainer
{
    [UnitTest]
    public void CompleteHandshakeAndAgreeOnSessionKeys()
    {
        When.A<object>("runs a full curve25519 + ed25519 key exchange over loopback and both sides derive the same keys",
            new object(),
            (ignored) =>
            {
                (SshTransport client, SshTransport server) = CreateConnectedPair();
                (byte[] hostKeyBlob, Func<byte[], byte[]> sign) = TestHostKeys.CreateEd25519();
                try
                {
                    SshClientKeyExchange clientKex = new SshClientKeyExchange(client);
                    TestServerKeyExchange serverKex = new TestServerKeyExchange(server, hostKeyBlob, sign);

                    Task<SshKeyExchangeResult> clientTask = clientKex.PerformAsync().AsTask();
                    Task serverTask = serverKex.RunAsync();
                    Task.WhenAll(clientTask, serverTask).GetAwaiter().GetResult();

                    SshKeyExchangeResult result = clientTask.Result;
                    SshSessionKeys serverKeys = serverKex.SessionKeys!;

                    bool[] results = new bool[5];
                    results[0] = result.Algorithms.KeyExchange == "curve25519-sha256";
                    results[1] = result.HostKey.Algorithm == "ssh-ed25519";
                    results[2] = result.ExchangeHash.AsSpan().SequenceEqual(serverKex.ExchangeHash!);
                    results[3] = result.SessionKeys.EncryptionKeyClientToServer.AsSpan()
                        .SequenceEqual(serverKeys.EncryptionKeyClientToServer);
                    results[4] = result.SessionKeys.IntegrityKeyServerToClient.AsSpan()
                        .SequenceEqual(serverKeys.IntegrityKeyServerToClient)
                        && result.SessionKeys.SessionId.Length == 32;
                    return results;
                }
                finally
                {
                    client.DisposeAsync().AsTask().GetAwaiter().GetResult();
                    server.DisposeAsync().AsTask().GetAwaiter().GetResult();
                }
            })
        .TheTest
        .ShouldPass(because =>
        {
            bool[] results = (bool[])because.Result;
            because.ItsTrue("curve25519 was negotiated", results[0]);
            because.ItsTrue("the ed25519 host key was used", results[1]);
            because.ItsTrue("client and server computed the same exchange hash", results[2]);
            because.ItsTrue("both sides derived the same c2s encryption key", results[3]);
            because.ItsTrue("both sides derived the same s2c integrity key and a 32-byte session id", results[4]);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RejectAnInvalidHostKeySignature()
    {
        When.A<object>("throws SshKeyExchangeException when the server signature does not verify",
            new object(),
            (ignored) =>
            {
                (SshTransport client, SshTransport server) = CreateConnectedPair();
                (byte[] hostKeyBlob, Func<byte[], byte[]> sign) = TestHostKeys.CreateEd25519();
                try
                {
                    // The client rejects the corrupted signature and throws before sending NEWKEYS,
                    // so the server would block waiting for NEWKEYS — cancel it once the client fails.
                    CancellationTokenSource serverCancellation = new CancellationTokenSource();
                    SshClientKeyExchange clientKex = new SshClientKeyExchange(client);
                    TestServerKeyExchange serverKex = new TestServerKeyExchange(server, hostKeyBlob, sign, corruptSignature: true);

                    Task<SshKeyExchangeResult> clientTask = clientKex.PerformAsync().AsTask();
                    Task serverTask = serverKex.RunAsync(null, serverCancellation.Token);

                    try
                    {
                        clientTask.GetAwaiter().GetResult();
                        return false;
                    }
                    catch (SshKeyExchangeException)
                    {
                        return true;
                    }
                    finally
                    {
                        serverCancellation.Cancel();
                        try
                        {
                            serverTask.Wait(TimeSpan.FromSeconds(5));
                        }
                        catch (Exception)
                        {
                        }
                        serverCancellation.Dispose();
                    }
                }
                finally
                {
                    client.DisposeAsync().AsTask().GetAwaiter().GetResult();
                    server.DisposeAsync().AsTask().GetAwaiter().GetResult();
                }
            })
        .TheTest
        .ShouldPass(because =>
        {
            because.ItsTrue("a corrupted signature is rejected", (bool)because.Result);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void CompleteHandshakeWithEcdhNistP256()
    {
        When.A<object>("negotiates ecdh-sha2-nistp256 when curve25519 is unavailable and still agrees",
            new object(),
            (ignored) =>
            {
                SshAlgorithmCatalog ecdhOnly = new SshAlgorithmCatalog(
                    keyExchange: new SshNameList("ecdh-sha2-nistp256"),
                    serverHostKey: new SshNameList("ecdsa-sha2-nistp256"),
                    encryption: new SshNameList("aes256-gcm@openssh.com"),
                    mac: new SshNameList("hmac-sha2-256"),
                    compression: new SshNameList("none"));

                (SshTransport client, SshTransport server) = CreateConnectedPair();
                (byte[] hostKeyBlob, Func<byte[], byte[]> sign) = TestHostKeys.CreateEcdsaNistP256();
                try
                {
                    SshClientKeyExchange clientKex = new SshClientKeyExchange(client, ecdhOnly);
                    TestServerKeyExchange serverKex = new TestServerKeyExchange(server, hostKeyBlob, sign);

                    Task<SshKeyExchangeResult> clientTask = clientKex.PerformAsync().AsTask();
                    Task serverTask = serverKex.RunAsync();
                    Task.WhenAll(clientTask, serverTask).GetAwaiter().GetResult();

                    SshKeyExchangeResult result = clientTask.Result;
                    bool kex = result.Algorithms.KeyExchange == "ecdh-sha2-nistp256";
                    bool agree = result.SessionKeys.EncryptionKeyServerToClient.AsSpan()
                        .SequenceEqual(serverKex.SessionKeys!.EncryptionKeyServerToClient);
                    return new bool[] { kex, agree };
                }
                finally
                {
                    client.DisposeAsync().AsTask().GetAwaiter().GetResult();
                    server.DisposeAsync().AsTask().GetAwaiter().GetResult();
                }
            })
        .TheTest
        .ShouldPass(because =>
        {
            bool[] results = (bool[])because.Result;
            because.ItsTrue("ecdh-sha2-nistp256 was negotiated", results[0]);
            because.ItsTrue("both sides agree on the derived keys", results[1]);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    private static (SshTransport Client, SshTransport Server) CreateConnectedPair()
    {
        (LoopbackDuplexStream clientStream, LoopbackDuplexStream serverStream) = LoopbackDuplexStream.CreatePair();
        SshTransport client = new SshTransport(clientStream, new SshTransportOptions("Bam.Ssh_Client"));
        SshTransport server = new SshTransport(serverStream, new SshTransportOptions("Bam.Ssh_Server"));
        Task clientConnect = client.ConnectAsync().AsTask();
        Task serverConnect = server.ConnectAsync().AsTask();
        Task.WhenAll(clientConnect, serverConnect).GetAwaiter().GetResult();
        return (client, server);
    }
}
