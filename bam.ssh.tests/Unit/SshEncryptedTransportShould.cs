using Bam.Ssh.Transport;
using Bam.Test;

namespace Bam.Ssh.Tests.Unit;

/// <summary>
/// End-to-end proof that Phase 4 encryption works through the real <see cref="SshTransport"/>: after a
/// full key exchange over loopback that activates the negotiated ciphers on both sides, application
/// packets are encrypted, authenticated, and decrypted correctly in both directions for every cipher
/// family — and a mid-session rekey preserves the session id while installing fresh keys.
/// </summary>
[UnitTestMenu("SshEncryptedTransportShould", Selector = "enc")]
public class SshEncryptedTransportShould : UnitTestMenuContainer
{
    [UnitTest]
    public void CarryEncryptedApplicationDataForEveryCipher()
    {
        When.A<object>("runs a keyed handshake then round-trips encrypted app packets both ways for each cipher",
            new object(),
            (ignored) =>
            {
                (string Cipher, string Mac)[] suites = new (string, string)[]
                {
                    (SshAlgorithmNames.ChaCha20Poly1305, SshAlgorithmNames.HmacSha2256),
                    (SshAlgorithmNames.Aes256Gcm, SshAlgorithmNames.HmacSha2256),
                    (SshAlgorithmNames.Aes128Gcm, SshAlgorithmNames.HmacSha2256),
                    (SshAlgorithmNames.Aes256Ctr, SshAlgorithmNames.HmacSha2256),
                    (SshAlgorithmNames.Aes256Ctr, SshAlgorithmNames.HmacSha2512),
                    (SshAlgorithmNames.Aes128Ctr, SshAlgorithmNames.HmacSha2256),
                };

                bool[] results = new bool[suites.Length];
                for (int i = 0; i < suites.Length; i++)
                {
                    results[i] = ExchangeEncryptedData(suites[i].Cipher, suites[i].Mac);
                }
                return results;
            })
        .TheTest
        .ShouldPass(because =>
        {
            bool[] results = (bool[])because.Result;
            because.ItsTrue("chacha20-poly1305 carries encrypted app data both ways", results[0]);
            because.ItsTrue("aes256-gcm carries encrypted app data both ways", results[1]);
            because.ItsTrue("aes128-gcm carries encrypted app data both ways", results[2]);
            because.ItsTrue("aes256-ctr+hmac-sha2-256 carries encrypted app data both ways", results[3]);
            because.ItsTrue("aes256-ctr+hmac-sha2-512 carries encrypted app data both ways", results[4]);
            because.ItsTrue("aes128-ctr carries encrypted app data both ways", results[5]);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RekeyPreservesSessionIdAndInstallsFreshKeys()
    {
        When.A<object>("rekeys over the encrypted transport, keeping the session id and changing the keys",
            new object(),
            (ignored) =>
            {
                SshAlgorithmCatalog catalog = ForceCipher(SshAlgorithmNames.ChaCha20Poly1305, SshAlgorithmNames.HmacSha2256);
                (SshTransport client, SshTransport server) = CreateConnectedPair();
                (byte[] hostKeyBlob, Func<byte[], byte[]> sign) = TestHostKeys.CreateEd25519();
                try
                {
                    SshClientKeyExchange clientKex = new SshClientKeyExchange(client, catalog);
                    TestServerKeyExchange serverKex = new TestServerKeyExchange(server, hostKeyBlob, sign);

                    Task<SshKeyExchangeResult> firstClient = clientKex.PerformAsync().AsTask();
                    Task firstServer = serverKex.RunAsync();
                    Task.WhenAll(firstClient, firstServer).GetAwaiter().GetResult();
                    SshKeyExchangeResult first = firstClient.Result;

                    // App data flows under the first keys.
                    bool firstFlow = RoundTripApplicationData(client, server, 0xA0);

                    // Rekey, preserving the original session id, over the now-encrypted transport.
                    Task<SshKeyExchangeResult> secondClient = clientKex.RekeyAsync(first.SessionKeys.SessionId).AsTask();
                    Task secondServer = serverKex.RunAsync(first.SessionKeys.SessionId);
                    Task.WhenAll(secondClient, secondServer).GetAwaiter().GetResult();
                    SshKeyExchangeResult second = secondClient.Result;

                    bool sessionPreserved = second.SessionKeys.SessionId.AsSpan().SequenceEqual(first.SessionKeys.SessionId);
                    bool keysRotated = !second.SessionKeys.EncryptionKeyClientToServer.AsSpan()
                        .SequenceEqual(first.SessionKeys.EncryptionKeyClientToServer);

                    // App data flows under the new keys.
                    bool secondFlow = RoundTripApplicationData(client, server, 0xB0);

                    return new bool[] { firstFlow, sessionPreserved, keysRotated, secondFlow };
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
            because.ItsTrue("app data flows under the first keys", results[0]);
            because.ItsTrue("the session id is preserved across the rekey", results[1]);
            because.ItsTrue("the rekey produced different encryption keys", results[2]);
            because.ItsTrue("app data flows under the rekeyed keys", results[3]);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    private static bool ExchangeEncryptedData(string cipher, string mac)
    {
        SshAlgorithmCatalog catalog = ForceCipher(cipher, mac);
        (SshTransport client, SshTransport server) = CreateConnectedPair();
        (byte[] hostKeyBlob, Func<byte[], byte[]> sign) = TestHostKeys.CreateEd25519();
        try
        {
            SshClientKeyExchange clientKex = new SshClientKeyExchange(client, catalog);
            TestServerKeyExchange serverKex = new TestServerKeyExchange(server, hostKeyBlob, sign);

            Task<SshKeyExchangeResult> clientTask = clientKex.PerformAsync().AsTask();
            Task serverTask = serverKex.RunAsync();
            Task.WhenAll(clientTask, serverTask).GetAwaiter().GetResult();

            if (clientTask.Result.Algorithms.EncryptionClientToServer != cipher)
            {
                return false;
            }
            return RoundTripApplicationData(client, server, 0x40);
        }
        finally
        {
            client.DisposeAsync().AsTask().GetAwaiter().GetResult();
            server.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }
    }

    private static bool RoundTripApplicationData(SshTransport client, SshTransport server, byte seed)
    {
        // Two packets each way to exercise post-handshake sequence/nonce/counter advancement.
        for (int i = 0; i < 2; i++)
        {
            byte[] clientToServer = Payload((byte)(seed + i), 32 + i * 17);
            client.SendPacketAsync(clientToServer).AsTask().GetAwaiter().GetResult();
            using SshIncomingPacket received = server.ReceivePacketAsync().AsTask().GetAwaiter().GetResult();
            if (!received.Payload.SequenceEqual(clientToServer))
            {
                return false;
            }

            byte[] serverToClient = Payload((byte)(seed + 0x08 + i), 48 + i * 11);
            server.SendPacketAsync(serverToClient).AsTask().GetAwaiter().GetResult();
            using SshIncomingPacket back = client.ReceivePacketAsync().AsTask().GetAwaiter().GetResult();
            if (!back.Payload.SequenceEqual(serverToClient))
            {
                return false;
            }
        }
        return true;
    }

    private static SshAlgorithmCatalog ForceCipher(string cipher, string mac)
    {
        return new SshAlgorithmCatalog(
            keyExchange: new SshNameList(SshAlgorithmNames.Curve25519Sha256),
            serverHostKey: new SshNameList(SshAlgorithmNames.SshEd25519),
            encryption: new SshNameList(cipher),
            mac: new SshNameList(mac),
            compression: new SshNameList(SshAlgorithmNames.None));
    }

    private static byte[] Payload(byte messageNumber, int length)
    {
        byte[] payload = new byte[length];
        payload[0] = messageNumber;
        for (int i = 1; i < length; i++)
        {
            payload[i] = (byte)(i * 3 + messageNumber);
        }
        return payload;
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
