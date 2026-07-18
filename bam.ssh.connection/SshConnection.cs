using System.Collections.Concurrent;
using System.Threading.Channels;
using Bam.Ssh.Transport;

namespace Bam.Ssh.Connection;

/// <summary>
/// The client role of the RFC 4254 connection protocol over an authenticated, encrypted
/// <see cref="SshTransport"/>. It is the sole reader and sole writer of the transport: a single
/// receive-dispatch loop routes channel messages (90–100) to the addressed <see cref="SshChannel"/>
/// and connection-generic messages (80–82) to the connection, while a single outbound writer serializes
/// every send. Multiple channels are multiplexed concurrently, each with its own flow-control windows.
/// The connection also owns automatic re-keying (RFC 4253 §9): when a byte or time threshold is crossed,
/// or the peer sends a KEXINIT, it pauses application traffic, runs the exchange by feeding key-exchange
/// packets from its loop to <see cref="SshClientKeyExchange.RekeyAsync"/>, and resumes. Disposing tears
/// down the loop, faults open channels, and disposes the transport.
/// </summary>
public sealed class SshConnection : IAsyncDisposable
{
    private readonly SshTransport _transport;
    private readonly byte[] _sessionId;
    private readonly ISshRekeyDriver _keyExchange;
    private readonly SshConnectionOptions _options;
    private readonly ISshLogger _logger;
    private readonly ISshChannelOpenHandler? _channelOpenHandler;

    private readonly ConcurrentDictionary<uint, SshChannel> _channels = new ConcurrentDictionary<uint, SshChannel>();
    private readonly ConcurrentDictionary<string, ISshChannelOpenHandler> _channelOpenHandlers = new ConcurrentDictionary<string, ISshChannelOpenHandler>(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, ISshGlobalRequestHandler> _globalRequestHandlers = new ConcurrentDictionary<string, ISshGlobalRequestHandler>(StringComparer.Ordinal);
    private readonly ConcurrentQueue<TaskCompletionSource<SshGlobalRequestReply>> _pendingGlobalRequests = new ConcurrentQueue<TaskCompletionSource<SshGlobalRequestReply>>();
    private readonly SemaphoreSlim _sendSemaphore = new SemaphoreSlim(1, 1);
    private readonly Channel<OutboundItem> _outbound =
        System.Threading.Channels.Channel.CreateUnbounded<OutboundItem>(new UnboundedChannelOptions { SingleReader = true });
    private readonly CancellationTokenSource _shutdown = new CancellationTokenSource();
    private readonly object _rekeySync = new object();

    private Task _dispatchTask = Task.CompletedTask;
    private Task _writerTask = Task.CompletedTask;
    private int _nextChannelId = -1;
    private long _bytesSinceRekey;
    private long _lastRekeyTicks;
    private volatile RekeyOperation? _activeRekey;
    private volatile bool _disposed;

    /// <summary>
    /// Initializes the connection over an authenticated transport and starts the dispatch loop.
    /// </summary>
    /// <param name="transport">The authenticated, keyed transport. Owned by this connection.</param>
    /// <param name="sessionId">The session identifier from key exchange (preserved across re-keys).</param>
    /// <param name="keyExchange">The re-key driver (client or server role); defaults to a client driver over the transport.</param>
    /// <param name="options">Connection tunables; defaults to <see cref="SshConnectionOptions.Default"/>.</param>
    /// <param name="logger">The logger; defaults to <see cref="NullSshLogger.Instance"/>.</param>
    /// <exception cref="ArgumentNullException">The transport or session id is null.</exception>
    /// <param name="channelOpenHandler">Handles peer-initiated channel opens (server role); null rejects them.</param>
    public SshConnection(
        SshTransport transport,
        byte[] sessionId,
        ISshRekeyDriver? keyExchange = null,
        SshConnectionOptions? options = null,
        ISshLogger? logger = null,
        ISshChannelOpenHandler? channelOpenHandler = null)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(sessionId);
        _transport = transport;
        _sessionId = sessionId;
        _keyExchange = keyExchange ?? new SshClientKeyExchange(transport);
        _options = options ?? SshConnectionOptions.Default;
        _logger = logger ?? NullSshLogger.Instance;
        _channelOpenHandler = channelOpenHandler;
        _lastRekeyTicks = Environment.TickCount64;
        _writerTask = WriterLoopAsync(_shutdown.Token);
        _dispatchTask = DispatchLoopAsync(_shutdown.Token);
    }

    /// <summary>
    /// Raised when the peer attempts to open a channel. The client rejects it (see
    /// <see cref="SshChannelOpenEventArgs"/>); the server role accepts opens via an
    /// <see cref="ISshChannelOpenHandler"/> supplied to the constructor.
    /// </summary>
    public event EventHandler<SshChannelOpenEventArgs>? ChannelOpenReceived;

    /// <summary>
    /// Gets a task that completes when the receive-dispatch loop ends — because the connection was
    /// disposed, the peer closed the transport, or the transport faulted. The server role awaits this to
    /// learn when a peer connection has terminated so it can release the per-connection session.
    /// </summary>
    public Task Completion => _dispatchTask;

    /// <summary>
    /// Registers a handler for peer-initiated channel opens of the given type, taking priority over the
    /// fallback handler supplied to the constructor. Used to accept forwarding channels — the client
    /// accepts <c>forwarded-tcpip</c>, the server accepts <c>direct-tcpip</c> alongside its <c>session</c>
    /// handler — without changing how the connection is constructed.
    /// </summary>
    /// <param name="channelType">The channel type to handle.</param>
    /// <param name="handler">The handler.</param>
    /// <exception cref="ArgumentException">The channel type is null or empty.</exception>
    /// <exception cref="ArgumentNullException">The handler is null.</exception>
    public void RegisterChannelOpenHandler(string channelType, ISshChannelOpenHandler handler)
    {
        ArgumentException.ThrowIfNullOrEmpty(channelType);
        ArgumentNullException.ThrowIfNull(handler);
        _channelOpenHandlers[channelType] = handler;
    }

    /// <summary>
    /// Removes a per-type channel-open handler previously registered with
    /// <see cref="RegisterChannelOpenHandler"/>.
    /// </summary>
    /// <param name="channelType">The channel type to stop handling.</param>
    /// <exception cref="ArgumentException">The channel type is null or empty.</exception>
    public void UnregisterChannelOpenHandler(string channelType)
    {
        ArgumentException.ThrowIfNullOrEmpty(channelType);
        _channelOpenHandlers.TryRemove(channelType, out _);
    }

    /// <summary>
    /// Registers a handler for peer-initiated global requests of the given name (for example a server
    /// handling <c>tcpip-forward</c>). Unregistered names are answered SSH_MSG_REQUEST_FAILURE.
    /// </summary>
    /// <param name="requestName">The global request name to handle.</param>
    /// <param name="handler">The handler.</param>
    /// <exception cref="ArgumentException">The request name is null or empty.</exception>
    /// <exception cref="ArgumentNullException">The handler is null.</exception>
    public void RegisterGlobalRequestHandler(string requestName, ISshGlobalRequestHandler handler)
    {
        ArgumentException.ThrowIfNullOrEmpty(requestName);
        ArgumentNullException.ThrowIfNull(handler);
        _globalRequestHandlers[requestName] = handler;
    }

    /// <summary>
    /// Removes a global-request handler previously registered with
    /// <see cref="RegisterGlobalRequestHandler"/>.
    /// </summary>
    /// <param name="requestName">The global request name to stop handling.</param>
    /// <exception cref="ArgumentException">The request name is null or empty.</exception>
    public void UnregisterGlobalRequestHandler(string requestName)
    {
        ArgumentException.ThrowIfNullOrEmpty(requestName);
        _globalRequestHandlers.TryRemove(requestName, out _);
    }

    /// <summary>
    /// Opens a <c>session</c> channel and wraps it for interactive/command use.
    /// </summary>
    /// <param name="cancellationToken">Cancels the open.</param>
    /// <returns>The opened session channel.</returns>
    /// <exception cref="SshChannelException">The peer refused the channel.</exception>
    public async ValueTask<SshSessionChannel> OpenSessionChannelAsync(CancellationToken cancellationToken = default)
    {
        SshChannel channel = await OpenChannelAsync(SshChannelOpenParameters.Session(_options), cancellationToken).ConfigureAwait(false);
        return new SshSessionChannel(channel);
    }

    /// <summary>
    /// Opens a channel of the given type and awaits the peer's confirmation.
    /// </summary>
    /// <param name="parameters">The channel-open parameters.</param>
    /// <param name="cancellationToken">Cancels the open.</param>
    /// <returns>The opened channel.</returns>
    /// <exception cref="ArgumentNullException">The parameters are null.</exception>
    /// <exception cref="ObjectDisposedException">The connection is disposed.</exception>
    /// <exception cref="SshChannelException">The peer refused the channel.</exception>
    public async ValueTask<SshChannel> OpenChannelAsync(SshChannelOpenParameters parameters, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ObjectDisposedException.ThrowIf(_disposed, this);

        uint localId = (uint)Interlocked.Increment(ref _nextChannelId);
        SshChannel channel = new SshChannel(this, localId, parameters.ChannelType, parameters.InitialWindowSize);
        _channels[localId] = channel;

        using (PooledBufferWriter writer = new PooledBufferWriter(48 + parameters.TypeSpecificData.Length))
        {
            SshWireWriter wire = new SshWireWriter(writer);
            wire.WriteByte((byte)SshMessageNumber.ChannelOpen);
            wire.WriteText(parameters.ChannelType);
            wire.WriteUInt32(localId);
            wire.WriteUInt32((uint)parameters.InitialWindowSize);
            wire.WriteUInt32((uint)parameters.MaximumPacketSize);
            wire.WriteRaw(parameters.TypeSpecificData.Span);
            await SendAsync(writer.WrittenMemory, cancellationToken).ConfigureAwait(false);
        }

        try
        {
            return await channel.OpenCompletion.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            _channels.TryRemove(localId, out _);
            throw;
        }
    }

    /// <summary>
    /// Sends a global (connection-level) request (RFC 4254 §4). When <paramref name="wantReply"/> is
    /// set, awaits SSH_MSG_REQUEST_SUCCESS/FAILURE and returns the outcome; otherwise returns true.
    /// </summary>
    /// <param name="requestName">The request name.</param>
    /// <param name="wantReply">Whether to request and await a reply.</param>
    /// <param name="requestData">The request-specific bytes.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>True on success (or when no reply was requested); false if the peer replied FAILURE.</returns>
    /// <exception cref="ArgumentNullException">The request name is null.</exception>
    public async ValueTask<bool> SendGlobalRequestAsync(string requestName, bool wantReply, ReadOnlyMemory<byte> requestData, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(requestName);
        if (!wantReply)
        {
            await SendGlobalRequestNoReplyAsync(requestName, requestData, cancellationToken).ConfigureAwait(false);
            return true;
        }
        SshGlobalRequestReply reply = await SendGlobalRequestWithReplyAsync(requestName, requestData, cancellationToken).ConfigureAwait(false);
        return reply.Success;
    }

    /// <summary>
    /// Sends a global (connection-level) request that wants a reply (RFC 4254 §4) and returns the outcome
    /// including the request-specific reply bytes — for example the bound port a <c>tcpip-forward</c> with
    /// port 0 returns in SSH_MSG_REQUEST_SUCCESS.
    /// </summary>
    /// <param name="requestName">The request name.</param>
    /// <param name="requestData">The request-specific bytes.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The reply (success flag plus any reply bytes).</returns>
    /// <exception cref="ArgumentNullException">The request name is null.</exception>
    public async ValueTask<SshGlobalRequestReply> SendGlobalRequestWithReplyAsync(string requestName, ReadOnlyMemory<byte> requestData, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(requestName);
        TaskCompletionSource<SshGlobalRequestReply> reply = new TaskCompletionSource<SshGlobalRequestReply>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pendingGlobalRequests.Enqueue(reply);
        using (PooledBufferWriter writer = new PooledBufferWriter(16 + requestData.Length))
        {
            SshWireWriter wire = new SshWireWriter(writer);
            wire.WriteByte((byte)SshMessageNumber.GlobalRequest);
            wire.WriteText(requestName);
            wire.WriteBoolean(true);
            wire.WriteRaw(requestData.Span);
            await SendAsync(writer.WrittenMemory, cancellationToken).ConfigureAwait(false);
        }
        return await reply.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask SendGlobalRequestNoReplyAsync(string requestName, ReadOnlyMemory<byte> requestData, CancellationToken cancellationToken)
    {
        using PooledBufferWriter writer = new PooledBufferWriter(16 + requestData.Length);
        SshWireWriter wire = new SshWireWriter(writer);
        wire.WriteByte((byte)SshMessageNumber.GlobalRequest);
        wire.WriteText(requestName);
        wire.WriteBoolean(false);
        wire.WriteRaw(requestData.Span);
        await SendAsync(writer.WrittenMemory, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Explicitly re-keys the connection now, preserving the session identifier, and returns when the
    /// exchange completes and the new ciphers are active.
    /// </summary>
    /// <param name="cancellationToken">Cancels the re-key.</param>
    public async ValueTask RekeyAsync(CancellationToken cancellationToken = default)
    {
        Task<SshKeyExchangeResult>? completion = await BeginRekeyAsync(prequeued: null, cancellationToken).ConfigureAwait(false);
        if (completion != null)
        {
            await completion.ConfigureAwait(false);
        }
    }

    internal async ValueTask SendAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
    {
        TaskCompletionSource completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!_outbound.Writer.TryWrite(new OutboundItem(payload, completion)))
        {
            throw new SshConnectionException("The connection is closed and cannot send.");
        }
        await completion.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    internal void PostSend(byte[] payload)
    {
        _outbound.Writer.TryWrite(new OutboundItem(payload, null));
    }

    internal void RemoveChannel(uint localId)
    {
        _channels.TryRemove(localId, out _);
    }

    private async Task WriterLoopAsync(CancellationToken cancellationToken)
    {
        try
        {
            while (await _outbound.Reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
            {
                while (_outbound.Reader.TryRead(out OutboundItem? item))
                {
                    await _sendSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
                    try
                    {
                        await _transport.SendPacketAsync(item.Payload, cancellationToken).ConfigureAwait(false);
                        item.Completion?.TrySetResult();
                    }
                    catch (Exception exception)
                    {
                        item.Completion?.TrySetException(exception);
                        if (exception is OperationCanceledException)
                        {
                            return;
                        }
                    }
                    finally
                    {
                        _sendSemaphore.Release();
                    }
                    CountTraffic(item.Payload.Length);
                }
                await TriggerRekeyIfDueAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // Shutdown.
        }
    }

    private async Task DispatchLoopAsync(CancellationToken cancellationToken)
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
                CountTraffic(packet.Length);
                await DispatchAsync(packet, cancellationToken).ConfigureAwait(false);
                await TriggerRekeyIfDueAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // Shutdown.
        }
        catch (Exception exception)
        {
            FaultAll(exception);
        }
    }

    private async ValueTask DispatchAsync(SshIncomingPacket packet, CancellationToken cancellationToken)
    {
        byte messageNumber = packet.MessageNumber;

        RekeyOperation? rekey = _activeRekey;
        if (rekey != null && IsKeyExchangeMessage(messageNumber))
        {
            rekey.Queue.Write(packet.Payload);
            if (messageNumber == (byte)SshMessageNumber.NewKeys)
            {
                await FinalizeRekeyAsync().ConfigureAwait(false);
            }
            return;
        }

        switch ((SshMessageNumber)messageNumber)
        {
            case SshMessageNumber.KexInit:
                await BeginRekeyAsync(packet.Payload.ToArray(), cancellationToken).ConfigureAwait(false);
                break;
            case SshMessageNumber.NewKeys:
                throw new SshConnectionException("Received SSH_MSG_NEWKEYS outside a key exchange.");
            case SshMessageNumber.GlobalRequest:
                await HandleGlobalRequestAsync(packet.Body.ToArray(), cancellationToken).ConfigureAwait(false);
                break;
            case SshMessageNumber.RequestSuccess:
                CompleteGlobalRequest(true, packet.Body);
                break;
            case SshMessageNumber.RequestFailure:
                CompleteGlobalRequest(false, ReadOnlySpan<byte>.Empty);
                break;
            case SshMessageNumber.ChannelOpen:
                await HandleChannelOpenAsync(ParseChannelOpen(packet.Body), cancellationToken).ConfigureAwait(false);
                break;
            case SshMessageNumber.ChannelOpenConfirmation:
                HandleChannelOpenConfirmation(packet.Body);
                break;
            case SshMessageNumber.ChannelOpenFailure:
                HandleChannelOpenFailure(packet.Body);
                break;
            case SshMessageNumber.ChannelWindowAdjust:
                HandleWindowAdjust(packet.Body);
                break;
            case SshMessageNumber.ChannelData:
                HandleChannelData(packet.Body);
                break;
            case SshMessageNumber.ChannelExtendedData:
                HandleChannelExtendedData(packet.Body);
                break;
            case SshMessageNumber.ChannelEof:
                HandleChannelEof(packet.Body);
                break;
            case SshMessageNumber.ChannelClose:
                HandleChannelClose(packet.Body);
                break;
            case SshMessageNumber.ChannelRequest:
                HandleChannelRequest(packet.Body);
                break;
            case SshMessageNumber.ChannelSuccess:
                HandleChannelReply(packet.Body, true);
                break;
            case SshMessageNumber.ChannelFailure:
                HandleChannelReply(packet.Body, false);
                break;
            default:
                if (_logger.IsEnabled(SshLogLevel.Debug))
                {
                    _logger.Log(SshLogLevel.Debug, "Ignoring unhandled connection message {0}.", messageNumber);
                }
                break;
        }
    }

    private static ParsedChannelOpen ParseChannelOpen(ReadOnlySpan<byte> body)
    {
        SshWireReader reader = new SshWireReader(body);
        string channelType = reader.ReadText();
        uint senderChannel = reader.ReadUInt32();
        uint initialWindow = reader.ReadUInt32();
        uint maximumPacket = reader.ReadUInt32();
        byte[] typeSpecific = reader.Remaining > 0 ? reader.ReadRaw(reader.Remaining).ToArray() : Array.Empty<byte>();
        return new ParsedChannelOpen(channelType, senderChannel, initialWindow, maximumPacket, typeSpecific);
    }

    private async ValueTask HandleChannelOpenAsync(ParsedChannelOpen open, CancellationToken cancellationToken)
    {
        ChannelOpenReceived?.Invoke(this, new SshChannelOpenEventArgs(open.ChannelType, open.SenderChannel, open.InitialWindow, open.MaximumPacket));

        // A handler registered for the specific channel type takes priority over the constructor fallback
        // (which the server uses for `session`); this lets both roles accept forwarding channels.
        if (!_channelOpenHandlers.TryGetValue(open.ChannelType, out ISshChannelOpenHandler? handler))
        {
            handler = _channelOpenHandler;
        }

        if (handler != null)
        {
            SshChannelOpenRequestContext context = new SshChannelOpenRequestContext(
                this, open.ChannelType, open.TypeSpecificData, open.SenderChannel, open.InitialWindow, open.MaximumPacket);
            await handler.HandleOpenAsync(context, cancellationToken).ConfigureAwait(false);
            if (!context.Resolved)
            {
                RejectInboundChannel(open.SenderChannel, SshChannelOpenFailureReason.UnknownChannelType, "Channel type not handled.");
            }
            return;
        }

        RejectInboundChannel(open.SenderChannel, SshChannelOpenFailureReason.UnknownChannelType, "Channel opening is not supported by this endpoint.");
    }

    internal SshChannel AcceptInboundChannel(string channelType, uint remoteId, uint remoteWindow, uint remoteMaximumPacket)
    {
        uint localId = (uint)Interlocked.Increment(ref _nextChannelId);
        SshChannel channel = new SshChannel(this, localId, channelType, _options.InitialWindowSize);
        _channels[localId] = channel;
        channel.CompleteOpen(remoteId, remoteWindow, remoteMaximumPacket);

        using PooledBufferWriter writer = new PooledBufferWriter(32);
        SshWireWriter wire = new SshWireWriter(writer);
        wire.WriteByte((byte)SshMessageNumber.ChannelOpenConfirmation);
        wire.WriteUInt32(remoteId);
        wire.WriteUInt32(localId);
        wire.WriteUInt32((uint)_options.InitialWindowSize);
        wire.WriteUInt32((uint)_options.MaximumPacketSize);
        PostSend(writer.WrittenSpan.ToArray());
        return channel;
    }

    internal void RejectInboundChannel(uint remoteId, SshChannelOpenFailureReason reason, string description)
    {
        using PooledBufferWriter writer = new PooledBufferWriter(64);
        SshWireWriter wire = new SshWireWriter(writer);
        wire.WriteByte((byte)SshMessageNumber.ChannelOpenFailure);
        wire.WriteUInt32(remoteId);
        wire.WriteUInt32((uint)reason);
        wire.WriteText(description);
        wire.WriteText(string.Empty);
        PostSend(writer.WrittenSpan.ToArray());
    }

    private sealed class ParsedChannelOpen
    {
        public ParsedChannelOpen(string channelType, uint senderChannel, uint initialWindow, uint maximumPacket, byte[] typeSpecificData)
        {
            ChannelType = channelType;
            SenderChannel = senderChannel;
            InitialWindow = initialWindow;
            MaximumPacket = maximumPacket;
            TypeSpecificData = typeSpecificData;
        }

        public string ChannelType { get; }

        public uint SenderChannel { get; }

        public uint InitialWindow { get; }

        public uint MaximumPacket { get; }

        public byte[] TypeSpecificData { get; }
    }

    private void HandleChannelOpenConfirmation(ReadOnlySpan<byte> body)
    {
        SshWireReader reader = new SshWireReader(body);
        uint recipient = reader.ReadUInt32();
        uint senderChannel = reader.ReadUInt32();
        uint initialWindow = reader.ReadUInt32();
        uint maximumPacket = reader.ReadUInt32();
        if (_channels.TryGetValue(recipient, out SshChannel? channel))
        {
            channel.CompleteOpen(senderChannel, initialWindow, maximumPacket);
        }
    }

    private void HandleChannelOpenFailure(ReadOnlySpan<byte> body)
    {
        SshWireReader reader = new SshWireReader(body);
        uint recipient = reader.ReadUInt32();
        uint reasonCode = reader.ReadUInt32();
        string description = reader.ReadText();
        if (_channels.TryRemove(recipient, out SshChannel? channel))
        {
            channel.FailOpen((SshChannelOpenFailureReason)reasonCode, description);
        }
    }

    private void HandleWindowAdjust(ReadOnlySpan<byte> body)
    {
        SshWireReader reader = new SshWireReader(body);
        uint recipient = reader.ReadUInt32();
        uint increment = reader.ReadUInt32();
        if (_channels.TryGetValue(recipient, out SshChannel? channel))
        {
            channel.AcceptWindowAdjust(increment);
        }
    }

    private void HandleChannelData(ReadOnlySpan<byte> body)
    {
        SshWireReader reader = new SshWireReader(body);
        uint recipient = reader.ReadUInt32();
        ReadOnlySpan<byte> data = reader.ReadString();
        if (_channels.TryGetValue(recipient, out SshChannel? channel))
        {
            channel.AcceptData(data);
        }
    }

    private void HandleChannelExtendedData(ReadOnlySpan<byte> body)
    {
        SshWireReader reader = new SshWireReader(body);
        uint recipient = reader.ReadUInt32();
        uint dataTypeCode = reader.ReadUInt32();
        ReadOnlySpan<byte> data = reader.ReadString();
        if (_channels.TryGetValue(recipient, out SshChannel? channel))
        {
            channel.AcceptExtendedData(dataTypeCode, data);
        }
    }

    private void HandleChannelEof(ReadOnlySpan<byte> body)
    {
        SshWireReader reader = new SshWireReader(body);
        uint recipient = reader.ReadUInt32();
        if (_channels.TryGetValue(recipient, out SshChannel? channel))
        {
            channel.AcceptEof();
        }
    }

    private void HandleChannelClose(ReadOnlySpan<byte> body)
    {
        SshWireReader reader = new SshWireReader(body);
        uint recipient = reader.ReadUInt32();
        if (_channels.TryGetValue(recipient, out SshChannel? channel))
        {
            channel.AcceptClose();
        }
    }

    private void HandleChannelRequest(ReadOnlySpan<byte> body)
    {
        SshWireReader reader = new SshWireReader(body);
        uint recipient = reader.ReadUInt32();
        string requestType = reader.ReadText();
        bool wantReply = reader.ReadBoolean();
        byte[] requestData = reader.ReadRaw(reader.Remaining).ToArray();
        if (_channels.TryGetValue(recipient, out SshChannel? channel))
        {
            channel.AcceptRequest(requestType, wantReply, requestData);
        }
    }

    private void HandleChannelReply(ReadOnlySpan<byte> body, bool success)
    {
        SshWireReader reader = new SshWireReader(body);
        uint recipient = reader.ReadUInt32();
        if (_channels.TryGetValue(recipient, out SshChannel? channel))
        {
            channel.AcceptRequestReply(success);
        }
    }

    private async ValueTask HandleGlobalRequestAsync(byte[] body, CancellationToken cancellationToken)
    {
        string requestName;
        bool wantReply;
        ReadOnlyMemory<byte> requestData;
        SshWireReader reader = new SshWireReader(body);
        requestName = reader.ReadText();
        wantReply = reader.ReadBoolean();
        requestData = reader.Remaining > 0
            ? new ReadOnlyMemory<byte>(body, body.Length - reader.Remaining, reader.Remaining)
            : ReadOnlyMemory<byte>.Empty;

        if (_globalRequestHandlers.TryGetValue(requestName, out ISshGlobalRequestHandler? handler))
        {
            SshGlobalRequestContext context = new SshGlobalRequestContext(this, requestName, requestData, wantReply);
            await handler.HandleRequestAsync(context, cancellationToken).ConfigureAwait(false);
            if (!context.Resolved && wantReply)
            {
                PostGlobalRequestFailure();
            }
            return;
        }

        if (wantReply)
        {
            PostGlobalRequestFailure();
        }
    }

    private void CompleteGlobalRequest(bool success, ReadOnlySpan<byte> data)
    {
        if (_pendingGlobalRequests.TryDequeue(out TaskCompletionSource<SshGlobalRequestReply>? reply))
        {
            reply.TrySetResult(new SshGlobalRequestReply(success, success ? data.ToArray() : Array.Empty<byte>()));
        }
    }

    internal void PostGlobalRequestSuccess(ReadOnlySpan<byte> data)
    {
        using PooledBufferWriter writer = new PooledBufferWriter(1 + data.Length);
        SshWireWriter wire = new SshWireWriter(writer);
        wire.WriteByte((byte)SshMessageNumber.RequestSuccess);
        wire.WriteRaw(data);
        PostSend(writer.WrittenSpan.ToArray());
    }

    internal void PostGlobalRequestFailure()
    {
        PostSend(new byte[] { (byte)SshMessageNumber.RequestFailure });
    }

    private async ValueTask TriggerRekeyIfDueAsync(CancellationToken cancellationToken)
    {
        if (_activeRekey != null)
        {
            return;
        }
        long bytes = Interlocked.Read(ref _bytesSinceRekey);
        bool byteThreshold = bytes >= _options.RekeyBytes;
        bool timeThreshold = (Environment.TickCount64 - Interlocked.Read(ref _lastRekeyTicks)) >= (long)_options.RekeyInterval.TotalMilliseconds;
        if (byteThreshold || timeThreshold)
        {
            await BeginRekeyAsync(prequeued: null, cancellationToken).ConfigureAwait(false);
        }
    }

    private async ValueTask<Task<SshKeyExchangeResult>?> BeginRekeyAsync(byte[]? prequeued, CancellationToken cancellationToken)
    {
        RekeyOperation operation;
        lock (_rekeySync)
        {
            if (_activeRekey != null)
            {
                if (prequeued != null)
                {
                    _activeRekey.Queue.Write(prequeued);
                }
                return _activeRekey.TaskOrNull;
            }
            operation = new RekeyOperation(new SshPacketQueue());
            if (prequeued != null)
            {
                operation.Queue.Write(prequeued);
            }
            _activeRekey = operation;
        }

        // Hold the send lock for the whole exchange so no application/control packet is written while
        // re-keying; only RekeyAsync writes (directly through the transport). Queued sends flush on release.
        await _sendSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
        Task<SshKeyExchangeResult> task = _keyExchange.RekeyAsync(_sessionId, operation.Queue, cancellationToken).AsTask();
        operation.Start(task);
        Interlocked.Exchange(ref _bytesSinceRekey, 0);
        Interlocked.Exchange(ref _lastRekeyTicks, Environment.TickCount64);
        if (_logger.IsEnabled(SshLogLevel.Information))
        {
            _logger.Log(SshLogLevel.Information, "Started re-key (peer-initiated={0}).", prequeued != null);
        }
        return task;
    }

    private async ValueTask FinalizeRekeyAsync()
    {
        RekeyOperation? operation = _activeRekey;
        if (operation == null)
        {
            return;
        }
        try
        {
            await operation.Task.ConfigureAwait(false);
            if (_logger.IsEnabled(SshLogLevel.Information))
            {
                _logger.Log(SshLogLevel.Information, "Re-key complete.");
            }
        }
        finally
        {
            operation.Queue.Complete();
            lock (_rekeySync)
            {
                _activeRekey = null;
            }
            _sendSemaphore.Release();
        }
    }

    private void CountTraffic(int byteCount)
    {
        Interlocked.Add(ref _bytesSinceRekey, byteCount);
    }

    private void FaultAll(Exception exception)
    {
        foreach (SshChannel channel in _channels.Values)
        {
            channel.Fault(exception);
        }
        while (_pendingGlobalRequests.TryDequeue(out TaskCompletionSource<SshGlobalRequestReply>? reply))
        {
            reply.TrySetException(exception);
        }
    }

    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        _shutdown.Cancel();
        _outbound.Writer.TryComplete();
        FaultAll(new SshConnectionException("The connection was disposed."));
        try
        {
            await Task.WhenAll(_dispatchTask, _writerTask).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Expected on shutdown.
        }
        catch (SshException)
        {
            // Transport teardown races are expected during disposal.
        }
        _shutdown.Dispose();
        _sendSemaphore.Dispose();
        await _transport.DisposeAsync().ConfigureAwait(false);
    }

    private static bool IsKeyExchangeMessage(byte messageNumber)
    {
        return messageNumber == (byte)SshMessageNumber.KexInit
            || messageNumber == (byte)SshMessageNumber.NewKeys
            || messageNumber == (byte)SshMessageNumber.KexExchangeSpecific30
            || messageNumber == (byte)SshMessageNumber.KexExchangeSpecific31;
    }

    private sealed class OutboundItem
    {
        public OutboundItem(ReadOnlyMemory<byte> payload, TaskCompletionSource? completion)
        {
            Payload = payload;
            Completion = completion;
        }

        public ReadOnlyMemory<byte> Payload { get; }

        public TaskCompletionSource? Completion { get; }
    }

    private sealed class RekeyOperation
    {
        private Task<SshKeyExchangeResult>? _task;

        public RekeyOperation(SshPacketQueue queue)
        {
            Queue = queue;
        }

        public SshPacketQueue Queue { get; }

        public Task<SshKeyExchangeResult> Task => _task ?? throw new InvalidOperationException("The re-key task has not started.");

        public Task<SshKeyExchangeResult>? TaskOrNull => _task;

        public void Start(Task<SshKeyExchangeResult> task)
        {
            _task = task;
        }
    }
}
