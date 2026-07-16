using System.Collections.Generic;
using Bam.Ssh.Connection;
using Bam.Ssh.Transport;

namespace Bam.Ssh.Tests.Unit;

/// <summary>
/// Runs a client <see cref="SshConnection"/> against a <see cref="TestConnectionServer"/> over a fully
/// keyed loopback pair (reusing the Phase 5 keyed-pair helper). Both peers run their own loops
/// concurrently; the server is cancelled during teardown so a client that stops mid-dialog cannot hang it.
/// </summary>
internal static class ConnectionTestSupport
{
    public static T Run<T>(SshConnectionOptions options, TestConnectionServer server, Func<SshConnection, TestConnectionServer, Task<T>> body)
    {
        (SshTransport clientTransport, SshTransport serverTransport, byte[] sessionId) = AuthenticationTestSupport.CreateKeyedPair();
        server.Attach(serverTransport, sessionId);
        CancellationTokenSource serverCancellation = new CancellationTokenSource();
        SshConnection connection = new SshConnection(
            clientTransport,
            sessionId,
            new SshClientKeyExchange(clientTransport),
            options);
        Task serverTask = server.RunAsync(serverCancellation.Token);
        try
        {
            return body(connection, server).GetAwaiter().GetResult();
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
            connection.DisposeAsync().AsTask().GetAwaiter().GetResult();
            serverTransport.DisposeAsync().AsTask().GetAwaiter().GetResult();
            serverCancellation.Dispose();
        }
    }
}

/// <summary>
/// A test-only peer that plays the RFC 4254 server role over a keyed loopback transport using the
/// production wire primitives: it confirms or rejects channel opens, answers session requests, echoes or
/// generates channel data (with real send/receive flow control), reports exit status, and honours a
/// client-initiated re-key. Configure behaviour via the public properties before running.
/// </summary>
internal sealed class TestConnectionServer
{
    private readonly SemaphoreSlim _sendLock = new SemaphoreSlim(1, 1);
    private readonly object _sendWindowGate = new object();
    private readonly List<byte> _received = new List<byte>();

    private SshTransport _transport = null!;
    private byte[] _sessionId = Array.Empty<byte>();
    private uint _clientChannelId;
    private uint _serverChannelId = 0;
    private int _clientMaxPacket;
    private long _sendWindowRemaining;
    private TaskCompletionSource _sendWindowSignal = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    private long _receiveRemaining;
    private TaskCompletionSource<bool>? _globalReply;

    // Configuration.
    public bool RejectOpen { get; set; }

    public bool RejectRequest { get; set; }

    public int AdvertisedWindow { get; set; } = 1 << 20;

    public int AdvertisedMaxPacket { get; set; } = 32 * 1024;

    public byte[] StandardOutput { get; set; } = Array.Empty<byte>();

    public byte[] StandardError { get; set; } = Array.Empty<byte>();

    public bool SendExitStatus { get; set; }

    public uint ExitCode { get; set; }

    public bool CloseAfterResponse { get; set; }

    // Observed state.
    public IReadOnlyList<byte> ReceivedData => _received;

    public void Attach(SshTransport transport, byte[] sessionId)
    {
        _transport = transport;
        _sessionId = sessionId;
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                using SshIncomingPacket packet = await _transport.ReceivePacketAsync(cancellationToken).ConfigureAwait(false);
                if (packet.IsEmpty)
                {
                    continue;
                }
                await HandleAsync(packet, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // Shutdown.
        }
    }

    /// <summary>
    /// Sends a global request to the client and awaits its reply, proving the client answers an unknown
    /// global request with SSH_MSG_REQUEST_FAILURE.
    /// </summary>
    public async Task<bool> ProbeGlobalRequestAsync(CancellationToken cancellationToken)
    {
        _globalReply = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        byte[] payload = BuildBlob(writer =>
        {
            writer.WriteByte((byte)SshMessageNumber.GlobalRequest);
            writer.WriteText("probe@bam.ssh");
            writer.WriteBoolean(true);
        });
        await SendAsync(payload, cancellationToken).ConfigureAwait(false);
        return await _globalReply.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task HandleAsync(SshIncomingPacket packet, CancellationToken cancellationToken)
    {
        switch ((SshMessageNumber)packet.MessageNumber)
        {
            case SshMessageNumber.KexInit:
                await HandleRekeyAsync(packet.Payload.ToArray(), cancellationToken).ConfigureAwait(false);
                break;
            case SshMessageNumber.ChannelOpen:
                await HandleOpenAsync(packet.Body.ToArray(), cancellationToken).ConfigureAwait(false);
                break;
            case SshMessageNumber.ChannelRequest:
                await HandleRequestAsync(packet.Body.ToArray(), cancellationToken).ConfigureAwait(false);
                break;
            case SshMessageNumber.ChannelData:
                await HandleDataAsync(packet.Body.ToArray(), cancellationToken).ConfigureAwait(false);
                break;
            case SshMessageNumber.ChannelWindowAdjust:
                HandleWindowAdjust(packet.Body.ToArray());
                break;
            case SshMessageNumber.GlobalRequest:
                await HandleGlobalRequestAsync(packet.Body.ToArray(), cancellationToken).ConfigureAwait(false);
                break;
            case SshMessageNumber.RequestSuccess:
                _globalReply?.TrySetResult(true);
                break;
            case SshMessageNumber.RequestFailure:
                _globalReply?.TrySetResult(false);
                break;
            case SshMessageNumber.ChannelEof:
            case SshMessageNumber.ChannelClose:
                break;
        }
    }

    private async Task HandleGlobalRequestAsync(byte[] body, CancellationToken cancellationToken)
    {
        bool wantReply;
        {
            SshWireReader reader = new SshWireReader(body);
            reader.ReadText(); // request name
            wantReply = reader.ReadBoolean();
        }
        if (wantReply)
        {
            await SendAsync(new byte[] { (byte)SshMessageNumber.RequestFailure }, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task HandleRekeyAsync(byte[] clientKexInit, CancellationToken cancellationToken)
    {
        (byte[] hostKeyBlob, Func<byte[], byte[]> sign) = TestHostKeys.CreateEd25519();
        TestServerKeyExchange serverKex = new TestServerKeyExchange(_transport, hostKeyBlob, sign);
        await serverKex.RunWithClientKexInitAsync(clientKexInit, _sessionId, cancellationToken).ConfigureAwait(false);
    }

    private async Task HandleOpenAsync(byte[] body, CancellationToken cancellationToken)
    {
        uint senderChannel;
        uint clientWindow;
        uint clientMaxPacket;
        {
            SshWireReader reader = new SshWireReader(body);
            reader.ReadText(); // channel type
            senderChannel = reader.ReadUInt32();
            clientWindow = reader.ReadUInt32();
            clientMaxPacket = reader.ReadUInt32();
        }
        _clientChannelId = senderChannel;
        _clientMaxPacket = (int)clientMaxPacket;
        _sendWindowRemaining = clientWindow;
        _receiveRemaining = AdvertisedWindow;

        if (RejectOpen)
        {
            byte[] failure = BuildBlob(writer =>
            {
                writer.WriteByte((byte)SshMessageNumber.ChannelOpenFailure);
                writer.WriteUInt32(senderChannel);
                writer.WriteUInt32((uint)SshChannelOpenFailureReason.AdministrativelyProhibited);
                writer.WriteText("Denied by test policy.");
                writer.WriteText(string.Empty);
            });
            await SendAsync(failure, cancellationToken).ConfigureAwait(false);
            return;
        }

        byte[] confirmation = BuildBlob(writer =>
        {
            writer.WriteByte((byte)SshMessageNumber.ChannelOpenConfirmation);
            writer.WriteUInt32(senderChannel);
            writer.WriteUInt32(_serverChannelId);
            writer.WriteUInt32((uint)AdvertisedWindow);
            writer.WriteUInt32((uint)AdvertisedMaxPacket);
        });
        await SendAsync(confirmation, cancellationToken).ConfigureAwait(false);
    }

    private async Task HandleRequestAsync(byte[] body, CancellationToken cancellationToken)
    {
        bool wantReply;
        {
            SshWireReader reader = new SshWireReader(body);
            reader.ReadUInt32(); // recipient
            reader.ReadText();   // request type
            wantReply = reader.ReadBoolean();
        }

        if (wantReply)
        {
            SshMessageNumber replyNumber = RejectRequest ? SshMessageNumber.ChannelFailure : SshMessageNumber.ChannelSuccess;
            byte[] reply = BuildBlob(writer =>
            {
                writer.WriteByte((byte)replyNumber);
                writer.WriteUInt32(_clientChannelId);
            });
            await SendAsync(reply, cancellationToken).ConfigureAwait(false);
        }

        if (RejectRequest)
        {
            return;
        }

        // Produce the scripted response on a separate task so this loop can keep reading the client's
        // WINDOW_ADJUST messages while the sender waits on the send window.
        _ = Task.Run(() => RespondAsync(cancellationToken), cancellationToken);
    }

    private async Task RespondAsync(CancellationToken cancellationToken)
    {
        try
        {
            if (StandardOutput.Length > 0)
            {
                await SendChannelDataAsync(StandardOutput, cancellationToken).ConfigureAwait(false);
            }
            if (StandardError.Length > 0)
            {
                await SendExtendedDataAsync(StandardError, cancellationToken).ConfigureAwait(false);
            }
            if (SendExitStatus)
            {
                byte[] exit = BuildBlob(writer =>
                {
                    writer.WriteByte((byte)SshMessageNumber.ChannelRequest);
                    writer.WriteUInt32(_clientChannelId);
                    writer.WriteText("exit-status");
                    writer.WriteBoolean(false);
                    writer.WriteUInt32(ExitCode);
                });
                await SendAsync(exit, cancellationToken).ConfigureAwait(false);
            }
            if (CloseAfterResponse)
            {
                await SendSingleAsync(SshMessageNumber.ChannelEof, cancellationToken).ConfigureAwait(false);
                await SendSingleAsync(SshMessageNumber.ChannelClose, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    private async Task HandleDataAsync(byte[] body, CancellationToken cancellationToken)
    {
        byte[] data;
        {
            SshWireReader reader = new SshWireReader(body);
            reader.ReadUInt32(); // recipient
            data = reader.ReadString().ToArray();
        }
        lock (_received)
        {
            _received.AddRange(data);
        }

        _receiveRemaining -= data.Length;
        if (_receiveRemaining <= AdvertisedWindow / 2)
        {
            uint increment = (uint)(AdvertisedWindow - _receiveRemaining);
            _receiveRemaining = AdvertisedWindow;
            byte[] adjust = BuildBlob(writer =>
            {
                writer.WriteByte((byte)SshMessageNumber.ChannelWindowAdjust);
                writer.WriteUInt32(_clientChannelId);
                writer.WriteUInt32(increment);
            });
            await SendAsync(adjust, cancellationToken).ConfigureAwait(false);
        }
    }

    private void HandleWindowAdjust(byte[] body)
    {
        SshWireReader reader = new SshWireReader(body);
        reader.ReadUInt32(); // recipient
        uint increment = reader.ReadUInt32();
        lock (_sendWindowGate)
        {
            _sendWindowRemaining += increment;
            TaskCompletionSource previous = _sendWindowSignal;
            _sendWindowSignal = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            previous.TrySetResult();
        }
    }

    private async Task SendChannelDataAsync(byte[] data, CancellationToken cancellationToken)
    {
        int offset = 0;
        while (offset < data.Length)
        {
            int want = Math.Min(data.Length - offset, _clientMaxPacket);
            int granted = await ReserveSendAsync(want, cancellationToken).ConfigureAwait(false);
            int start = offset;
            int length = granted;
            byte[] message = BuildBlob(writer =>
            {
                writer.WriteByte((byte)SshMessageNumber.ChannelData);
                writer.WriteUInt32(_clientChannelId);
                writer.WriteString(data.AsSpan(start, length));
            });
            await SendAsync(message, cancellationToken).ConfigureAwait(false);
            offset += granted;
        }
    }

    private async Task SendExtendedDataAsync(byte[] data, CancellationToken cancellationToken)
    {
        int offset = 0;
        while (offset < data.Length)
        {
            int want = Math.Min(data.Length - offset, _clientMaxPacket);
            int granted = await ReserveSendAsync(want, cancellationToken).ConfigureAwait(false);
            int start = offset;
            int length = granted;
            byte[] message = BuildBlob(writer =>
            {
                writer.WriteByte((byte)SshMessageNumber.ChannelExtendedData);
                writer.WriteUInt32(_clientChannelId);
                writer.WriteUInt32((uint)SshExtendedDataType.StandardError);
                writer.WriteString(data.AsSpan(start, length));
            });
            await SendAsync(message, cancellationToken).ConfigureAwait(false);
            offset += granted;
        }
    }

    private async Task<int> ReserveSendAsync(int maxWanted, CancellationToken cancellationToken)
    {
        while (true)
        {
            Task wait;
            lock (_sendWindowGate)
            {
                if (_sendWindowRemaining > 0)
                {
                    int grant = (int)Math.Min(maxWanted, _sendWindowRemaining);
                    _sendWindowRemaining -= grant;
                    return grant;
                }
                wait = _sendWindowSignal.Task;
            }
            await wait.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task SendSingleAsync(SshMessageNumber messageNumber, CancellationToken cancellationToken)
    {
        byte[] payload = BuildBlob(writer =>
        {
            writer.WriteByte((byte)messageNumber);
            writer.WriteUInt32(_clientChannelId);
        });
        await SendAsync(payload, cancellationToken).ConfigureAwait(false);
    }

    private async Task SendAsync(byte[] payload, CancellationToken cancellationToken)
    {
        await _sendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await _transport.SendPacketAsync(payload, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _sendLock.Release();
        }
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
