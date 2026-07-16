using Bam.Ssh.Authentication;
using Bam.Ssh.Transport;

namespace Bam.Ssh.Tests.Unit;

/// <summary>
/// Builds a pair of fully keyed loopback transports (version exchange + key exchange complete) sharing
/// one session identifier, and runs a client authentication dialog against a <see cref="TestUserAuthServer"/>.
/// Mirrors the Phase 4 keyed-pair pattern; the server is driven under a cancellation token so a client
/// that stops after exhausting its methods cannot hang the server on a pending receive.
/// </summary>
internal static class AuthenticationTestSupport
{
    public static (SshTransport Client, SshTransport Server, byte[] SessionId) CreateKeyedPair()
    {
        (LoopbackDuplexStream clientStream, LoopbackDuplexStream serverStream) = LoopbackDuplexStream.CreatePair();
        SshTransport client = new SshTransport(clientStream, new SshTransportOptions("Bam.Ssh_Client"));
        SshTransport server = new SshTransport(serverStream, new SshTransportOptions("Bam.Ssh_Server"));
        Task.WhenAll(client.ConnectAsync().AsTask(), server.ConnectAsync().AsTask()).GetAwaiter().GetResult();

        (byte[] hostKeyBlob, Func<byte[], byte[]> sign) = TestHostKeys.CreateEd25519();
        SshClientKeyExchange clientKex = new SshClientKeyExchange(client);
        TestServerKeyExchange serverKex = new TestServerKeyExchange(server, hostKeyBlob, sign);
        Task<SshKeyExchangeResult> clientKexTask = clientKex.PerformAsync().AsTask();
        Task serverKexTask = serverKex.RunAsync();
        Task.WhenAll(clientKexTask, serverKexTask).GetAwaiter().GetResult();

        return (client, server, clientKexTask.Result.SessionKeys.SessionId);
    }

    /// <summary>
    /// Runs the client authenticator against the server over a fresh keyed pair and returns the result.
    /// </summary>
    public static SshAuthenticationResult RunAuthentication(
        TestUserAuthServer server,
        string userName,
        IReadOnlyList<ISshAuthenticationMethod> methods,
        ISshBannerSink? bannerSink = null)
    {
        (SshTransport client, SshTransport serverTransport, byte[] sessionId) = CreateKeyedPair();
        server.SessionId = sessionId;
        SshUserAuthenticator authenticator = new SshUserAuthenticator(client, sessionId, bannerSink);
        CancellationTokenSource serverCancellation = new CancellationTokenSource();
        try
        {
            Task<SshAuthenticationResult> clientTask = authenticator.AuthenticateAsync(userName, methods).AsTask();
            Task serverTask = server.RunAsync(serverTransport, serverCancellation.Token);
            try
            {
                return clientTask.GetAwaiter().GetResult();
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
                    // Best-effort teardown: the server is expected to be mid-receive when cancelled after
                    // a client that failed all methods; that cancellation must not mask the client result.
                }
            }
        }
        finally
        {
            serverCancellation.Dispose();
            client.DisposeAsync().AsTask().GetAwaiter().GetResult();
            serverTransport.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }
    }
}

/// <summary>
/// A test-only server that plays the RFC 4252 server role over a keyed loopback transport, using the
/// production wire primitives and the production transport host-key verifiers to check publickey
/// signatures — proving the client's signature blobs are byte-compatible with what a real server runs.
/// Configure the accepted credential(s) via the public fields before calling <see cref="RunAsync"/>.
/// </summary>
internal sealed class TestUserAuthServer
{
    private static readonly SshNameList DefaultContinue =
        new SshNameList(SshAuthenticationNames.PublicKey, SshAuthenticationNames.Password, SshAuthenticationNames.KeyboardInteractive);

    public byte[] SessionId { get; set; } = Array.Empty<byte>();

    public string ExpectedUser { get; set; } = "tester";

    public string? AcceptPassword { get; set; }

    public byte[]? AcceptPublicKeyBlob { get; set; }

    public string? KeyboardInteractivePrompt { get; set; }

    public string? KeyboardInteractiveAnswer { get; set; }

    public string? Banner { get; set; }

    public SshNameList ContinueMethods { get; set; } = DefaultContinue;

    public async Task RunAsync(SshTransport transport, CancellationToken cancellationToken)
    {
        await AcceptServiceAsync(transport, cancellationToken).ConfigureAwait(false);
        if (Banner is not null)
        {
            await SendBannerAsync(transport, Banner, cancellationToken).ConfigureAwait(false);
        }

        while (true)
        {
            byte[] request = await ReceiveAsync(transport, SshMessageNumber.UserauthRequest, cancellationToken).ConfigureAwait(false);

            // All wire-reader use is synchronous and confined to this block — a ref struct cannot cross
            // an await, so the keyboard-interactive branch only sets a flag here and awaits below.
            bool accepted;
            bool needsKeyboardInteractive = false;
            {
                SshWireReader reader = new SshWireReader(request);
                reader.ReadByte(); // message number
                string user = reader.ReadText();
                string service = reader.ReadText();
                string method = reader.ReadText();

                if (user != ExpectedUser)
                {
                    accepted = false;
                }
                else if (method == SshAuthenticationNames.Password && AcceptPassword is not null)
                {
                    reader.ReadBoolean(); // change-password flag
                    accepted = reader.ReadText() == AcceptPassword;
                }
                else if (method == SshAuthenticationNames.PublicKey && AcceptPublicKeyBlob is not null)
                {
                    accepted = VerifyPublicKey(user, service, reader);
                }
                else if (method == SshAuthenticationNames.KeyboardInteractive && KeyboardInteractiveAnswer is not null)
                {
                    needsKeyboardInteractive = true;
                    accepted = false;
                }
                else
                {
                    accepted = false;
                }
            }

            if (needsKeyboardInteractive)
            {
                accepted = await RunKeyboardInteractiveAsync(transport, cancellationToken).ConfigureAwait(false);
            }

            if (accepted)
            {
                await SendAsync(transport, new byte[] { (byte)SshMessageNumber.UserauthSuccess }, cancellationToken).ConfigureAwait(false);
                return;
            }
            await SendFailureAsync(transport, cancellationToken).ConfigureAwait(false);
        }
    }

    private bool VerifyPublicKey(string user, string service, SshWireReader reader)
    {
        bool hasSignature = reader.ReadBoolean();
        string algorithm = reader.ReadText();
        byte[] publicKeyBlob = reader.ReadString().ToArray();
        if (!hasSignature)
        {
            return false;
        }
        byte[] signature = reader.ReadString().ToArray();
        if (!publicKeyBlob.AsSpan().SequenceEqual(AcceptPublicKeyBlob))
        {
            return false;
        }

        byte[] signedData = BuildBlob(writer =>
        {
            writer.WriteString(SessionId);
            writer.WriteByte((byte)SshMessageNumber.UserauthRequest);
            writer.WriteText(user);
            writer.WriteText(service);
            writer.WriteText(SshAuthenticationNames.PublicKey);
            writer.WriteBoolean(true);
            writer.WriteText(algorithm);
            writer.WriteString(publicKeyBlob);
        });

        ISshHostKey verifier = SshHostKeyParser.Parse(publicKeyBlob);
        return verifier.Verify(signedData, signature);
    }

    private async Task<bool> RunKeyboardInteractiveAsync(SshTransport transport, CancellationToken cancellationToken)
    {
        byte[] infoRequest = BuildBlob(writer =>
        {
            writer.WriteByte(SshUserAuthMessageNumber.InformationRequest);
            writer.WriteText(string.Empty); // name
            writer.WriteText(string.Empty); // instruction
            writer.WriteText(string.Empty); // language
            writer.WriteUInt32(1);
            writer.WriteText(KeyboardInteractivePrompt ?? "Password: ");
            writer.WriteBoolean(false); // no echo
        });
        await SendAsync(transport, infoRequest, cancellationToken).ConfigureAwait(false);

        byte[] response = await ReceiveMethodSpecificAsync(transport, SshUserAuthMessageNumber.InformationResponse, cancellationToken).ConfigureAwait(false);
        SshWireReader reader = new SshWireReader(response);
        reader.ReadByte(); // message number
        uint count = reader.ReadUInt32();
        if (count != 1)
        {
            return false;
        }
        string answer = reader.ReadText();
        return answer == KeyboardInteractiveAnswer;
    }

    private async Task AcceptServiceAsync(SshTransport transport, CancellationToken cancellationToken)
    {
        byte[] request = await ReceiveAsync(transport, SshMessageNumber.ServiceRequest, cancellationToken).ConfigureAwait(false);
        SshWireReader reader = new SshWireReader(request);
        reader.ReadByte();
        string service = reader.ReadText();
        byte[] accept = BuildBlob(writer =>
        {
            writer.WriteByte((byte)SshMessageNumber.ServiceAccept);
            writer.WriteText(service);
        });
        await SendAsync(transport, accept, cancellationToken).ConfigureAwait(false);
    }

    private async Task SendBannerAsync(SshTransport transport, string message, CancellationToken cancellationToken)
    {
        byte[] banner = BuildBlob(writer =>
        {
            writer.WriteByte((byte)SshMessageNumber.UserauthBanner);
            writer.WriteText(message);
            writer.WriteText(string.Empty);
        });
        await SendAsync(transport, banner, cancellationToken).ConfigureAwait(false);
    }

    private async Task SendFailureAsync(SshTransport transport, CancellationToken cancellationToken)
    {
        byte[] failure = BuildBlob(writer =>
        {
            writer.WriteByte((byte)SshMessageNumber.UserauthFailure);
            writer.WriteNameList(ContinueMethods);
            writer.WriteBoolean(false);
        });
        await SendAsync(transport, failure, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<byte[]> ReceiveAsync(SshTransport transport, SshMessageNumber expected, CancellationToken cancellationToken)
    {
        using SshIncomingPacket packet = await transport.ReceivePacketAsync(cancellationToken).ConfigureAwait(false);
        if (packet.IsEmpty || packet.MessageNumber != (byte)expected)
        {
            throw new InvalidOperationException($"Test server expected {(byte)expected} but got {(packet.IsEmpty ? 0 : packet.MessageNumber)}.");
        }
        return packet.Payload.ToArray();
    }

    private static async Task<byte[]> ReceiveMethodSpecificAsync(SshTransport transport, byte expected, CancellationToken cancellationToken)
    {
        using SshIncomingPacket packet = await transport.ReceivePacketAsync(cancellationToken).ConfigureAwait(false);
        if (packet.IsEmpty || packet.MessageNumber != expected)
        {
            throw new InvalidOperationException($"Test server expected method-specific {expected} but got {(packet.IsEmpty ? 0 : packet.MessageNumber)}.");
        }
        return packet.Payload.ToArray();
    }

    private static async Task SendAsync(SshTransport transport, byte[] payload, CancellationToken cancellationToken)
    {
        await transport.SendPacketAsync(payload, cancellationToken).ConfigureAwait(false);
    }

    private static byte[] BuildBlob(Action<SshWireWriter> write)
    {
        PooledBufferWriter buffer = new PooledBufferWriter(128);
        try
        {
            SshWireWriter writer = new SshWireWriter(buffer);
            write(writer);
            return buffer.WrittenSpan.ToArray();
        }
        finally
        {
            buffer.Dispose();
        }
    }
}
