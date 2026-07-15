using System.Buffers;
using System.Diagnostics;

namespace Bam.Ssh.Transport;

/// <summary>
/// The SSH transport-layer façade over a byte connection: performs the RFC 4253 §4.2 identification
/// exchange, then sends and receives binary packets through the Phase 1 framing, maintaining
/// per-direction sequence numbers and dispatching the transport-generic messages (IGNORE, DEBUG,
/// UNIMPLEMENTED, DISCONNECT). It runs cleartext until <see cref="ApplyKeys"/> installs real ciphers
/// after key exchange (Phases 3–4). Upper layers (kex, auth, connection) build their own payloads
/// and drive this through <see cref="SendPacketAsync"/> / <see cref="ReceivePacketAsync"/>.
/// Owns the underlying transport and disposes it. Not thread-safe; callers serialize sends and reads.
/// </summary>
public sealed class SshTransport : IAsyncDisposable
{
    private readonly ISshDuplexStream _stream;
    private readonly SshTransportOptions _options;
    private readonly ISshLogger _logger;
    private readonly SshVersionExchange _versionExchange;
    private readonly SshPacketWriter _writer;
    private readonly SshPacketReader _reader;
    private SshVersionExchangeResult _versionResult;
    private bool _connected;

    /// <summary>
    /// Initializes a transport over the given byte stream.
    /// </summary>
    /// <param name="stream">The byte transport (e.g. <see cref="SshTcpDuplexStream"/>). Owned by this transport.</param>
    /// <param name="options">Transport options; defaults to <see cref="SshTransportOptions.Default"/>.</param>
    /// <param name="logger">The logger; defaults to <see cref="NullSshLogger.Instance"/>.</param>
    /// <exception cref="ArgumentNullException">The stream is null.</exception>
    public SshTransport(ISshDuplexStream stream, SshTransportOptions? options = null, ISshLogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(stream);
        _stream = stream;
        _options = options ?? SshTransportOptions.Default;
        _logger = logger ?? NullSshLogger.Instance;
        _versionExchange = new SshVersionExchange(_stream, _options);
        _writer = new SshPacketWriter(_stream.Output, NonePacketCipher.Instance);
        _reader = new SshPacketReader(_stream.Input, NonePacketCipher.Instance, _options.PacketLimits);
    }

    /// <summary>
    /// Gets the identification strings exchanged during <see cref="ConnectAsync"/>. Key exchange
    /// consumes the raw bytes to build the exchange hash.
    /// </summary>
    /// <exception cref="InvalidOperationException">Accessed before <see cref="ConnectAsync"/> completed.</exception>
    public SshVersionExchangeResult VersionExchange
    {
        get
        {
            if (!_connected)
            {
                throw new InvalidOperationException("The version exchange has not completed; call ConnectAsync first.");
            }
            return _versionResult;
        }
    }

    /// <summary>
    /// Performs the identification-string exchange, after which the packet protocol is active.
    /// </summary>
    /// <param name="cancellationToken">Cancels the handshake.</param>
    /// <returns>The exchange result (also available via <see cref="VersionExchange"/>).</returns>
    public async ValueTask<SshVersionExchangeResult> ConnectAsync(CancellationToken cancellationToken = default)
    {
        using Activity? activity = SshActivitySource.Instance.StartActivity("ssh.version_exchange");
        SshIdentificationString local = _options.CreateLocalIdentification();
        _versionResult = await _versionExchange.ExchangeAsync(local, cancellationToken).ConfigureAwait(false);
        _connected = true;
        if (_logger.IsEnabled(SshLogLevel.Information))
        {
            _logger.Log(SshLogLevel.Information, "SSH version exchange complete; peer is {0}.", _versionResult.Remote.ToString());
        }
        return _versionResult;
    }

    /// <summary>
    /// Sends one packet with the given payload (message number followed by message fields).
    /// </summary>
    /// <param name="payload">The packet payload.</param>
    /// <param name="cancellationToken">Cancels the send.</param>
    /// <returns>A task that completes when the packet is written and flushed.</returns>
    public async ValueTask SendPacketAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken = default)
    {
        EnsureConnected();
        if (_logger.IsEnabled(SshLogLevel.Trace) && payload.Length > 0)
        {
            _logger.Log(SshLogLevel.Trace, "Sending packet type {0} ({1} payload bytes), sequence {2}.",
                payload.Span[0], payload.Length, _writer.NextSequenceNumber);
        }
        await _writer.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Receives the next application-relevant packet, transparently consuming and responding to the
    /// transport-generic messages: IGNORE is discarded, DEBUG is logged and discarded, DISCONNECT
    /// throws <see cref="SshDisconnectException"/>. UNIMPLEMENTED and all other messages are returned
    /// to the caller.
    /// </summary>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>The next payload for an upper layer; dispose it after parsing.</returns>
    /// <exception cref="SshDisconnectException">The peer sent SSH_MSG_DISCONNECT.</exception>
    public async ValueTask<SshIncomingPacket> ReceivePacketAsync(CancellationToken cancellationToken = default)
    {
        EnsureConnected();
        while (true)
        {
            SshIncomingPacket packet = await _reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            if (packet.IsEmpty)
            {
                packet.Dispose();
                throw new SshTransportException("Received an empty packet with no message number.", SshDisconnectReason.ProtocolError);
            }

            SshMessageNumber messageNumber = (SshMessageNumber)packet.MessageNumber;
            switch (messageNumber)
            {
                case SshMessageNumber.Ignore:
                    packet.Dispose();
                    continue;
                case SshMessageNumber.Debug:
                    LogDebugMessage(packet);
                    packet.Dispose();
                    continue;
                case SshMessageNumber.Disconnect:
                    SshDisconnectException disconnect = ReadDisconnect(packet);
                    packet.Dispose();
                    throw disconnect;
                default:
                    return packet;
            }
        }
    }

    /// <summary>
    /// Sends SSH_MSG_DISCONNECT with the given reason and description, then closes the transport.
    /// </summary>
    /// <param name="reason">The disconnect reason code.</param>
    /// <param name="description">A human-readable description (may be empty).</param>
    /// <param name="cancellationToken">Cancels the send.</param>
    /// <returns>A task that completes when the disconnect has been sent and the transport closed.</returns>
    public async ValueTask SendDisconnectAsync(SshDisconnectReason reason, string description, CancellationToken cancellationToken = default)
    {
        EnsureConnected();
        ArgumentNullException.ThrowIfNull(description);
        using (PooledBufferWriter payload = new PooledBufferWriter(32 + description.Length))
        {
            SshWireWriter writer = new SshWireWriter(payload);
            writer.WriteByte((byte)SshMessageNumber.Disconnect);
            writer.WriteUInt32((uint)reason);
            writer.WriteText(description);
            writer.WriteText(string.Empty);
            await _writer.WriteAsync(payload.WrittenMemory, cancellationToken).ConfigureAwait(false);
        }
        await _stream.CloseAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Installs newly negotiated ciphers for both directions, effective for subsequent packets.
    /// Called by key exchange when SSH_MSG_NEWKEYS is processed. Sequence numbers continue unbroken.
    /// </summary>
    /// <param name="inbound">The cipher for received packets.</param>
    /// <param name="outbound">The cipher for sent packets.</param>
    /// <exception cref="ArgumentNullException">A cipher is null.</exception>
    public void ApplyKeys(ISshPacketCipher inbound, ISshPacketCipher outbound)
    {
        ArgumentNullException.ThrowIfNull(inbound);
        ArgumentNullException.ThrowIfNull(outbound);
        _reader.SwapCipher(inbound);
        _writer.SwapCipher(outbound);
        if (_logger.IsEnabled(SshLogLevel.Debug))
        {
            _logger.Log(SshLogLevel.Debug, "New keys applied to both directions.");
        }
    }

    /// <summary>
    /// Closes and releases the underlying transport.
    /// </summary>
    /// <returns>A task that completes when the transport is disposed.</returns>
    public async ValueTask DisposeAsync()
    {
        await _stream.DisposeAsync().ConfigureAwait(false);
    }

    private void LogDebugMessage(in SshIncomingPacket packet)
    {
        if (!_logger.IsEnabled(SshLogLevel.Debug))
        {
            return;
        }
        try
        {
            SshWireReader reader = new SshWireReader(packet.Body);
            bool alwaysDisplay = reader.ReadBoolean();
            string message = reader.ReadText();
            _logger.Log(SshLogLevel.Debug, "Peer SSH_MSG_DEBUG (alwaysDisplay={0}): {1}", alwaysDisplay, message);
        }
        catch (SshWireFormatException)
        {
            _logger.Log(SshLogLevel.Warning, "Received a malformed SSH_MSG_DEBUG message.");
        }
    }

    private static SshDisconnectException ReadDisconnect(in SshIncomingPacket packet)
    {
        try
        {
            SshWireReader reader = new SshWireReader(packet.Body);
            uint reasonCode = reader.ReadUInt32();
            string description = reader.ReadText();
            return new SshDisconnectException((SshDisconnectReason)reasonCode, description);
        }
        catch (SshWireFormatException)
        {
            return new SshDisconnectException(SshDisconnectReason.ProtocolError, "malformed disconnect message");
        }
    }

    private void EnsureConnected()
    {
        if (!_connected)
        {
            throw new InvalidOperationException("The transport is not connected; call ConnectAsync first.");
        }
    }
}
