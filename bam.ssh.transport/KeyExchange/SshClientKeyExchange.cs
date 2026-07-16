using System.Buffers;
using System.Diagnostics;

namespace Bam.Ssh.Transport;

/// <summary>
/// Drives the client role of an SSH key exchange over an <see cref="SshTransport"/> (RFC 4253 §7,
/// RFC 5656 for ECDH): sends the local KEXINIT, negotiates algorithms with the peer's, runs the
/// chosen key-agreement method, verifies the server's host-key signature over the exchange hash, and
/// exchanges SSH_MSG_NEWKEYS. On success it produces the negotiated algorithms, the verified host
/// key, and the derived <see cref="SshSessionKeys"/> — which Phase 4 turns into live ciphers via
/// <see cref="SshTransport.ApplyKeys"/>. A failed signature verification is a hard rejection.
/// </summary>
public sealed class SshClientKeyExchange : ISshRekeyDriver
{
    // Derive a uniform, generous length for each key. Because RFC 4253 §7.2 derivation is a prefix
    // relationship, Phase 4 slices the exact prefix each negotiated cipher/MAC needs (max: 64-byte
    // hmac-sha2-512 integrity key). 64 bytes covers every planned algorithm.
    private const int DerivedKeyLength = 64;

    private readonly SshTransport _transport;
    private readonly SshAlgorithmCatalog _catalog;
    private readonly ISshRandom _random;
    private readonly ISshLogger _logger;

    /// <summary>
    /// Initializes the client key exchange.
    /// </summary>
    /// <param name="transport">The connected transport (version exchange must have completed).</param>
    /// <param name="catalog">The local algorithm catalog; defaults to <see cref="SshAlgorithmCatalog.Default"/>.</param>
    /// <param name="random">The randomness source; defaults to <see cref="SecureSshRandom.Instance"/>.</param>
    /// <param name="logger">The logger; defaults to <see cref="NullSshLogger.Instance"/>.</param>
    /// <exception cref="ArgumentNullException">The transport is null.</exception>
    public SshClientKeyExchange(
        SshTransport transport,
        SshAlgorithmCatalog? catalog = null,
        ISshRandom? random = null,
        ISshLogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(transport);
        _transport = transport;
        _catalog = catalog ?? SshAlgorithmCatalog.Default;
        _random = random ?? SecureSshRandom.Instance;
        _logger = logger ?? NullSshLogger.Instance;
    }

    /// <summary>
    /// Performs the full client-side initial key exchange and activates the negotiated ciphers on the
    /// transport. The session identifier is the exchange hash of this first exchange.
    /// </summary>
    /// <param name="cancellationToken">Cancels the exchange.</param>
    /// <returns>The negotiated algorithms, verified host key, and derived session keys.</returns>
    /// <exception cref="SshKeyExchangeException">Negotiation failed, a message was malformed, or the host-key signature did not verify.</exception>
    public ValueTask<SshKeyExchangeResult> PerformAsync(CancellationToken cancellationToken = default)
    {
        return ExecuteAsync(existingSessionId: null, _transport, cancellationToken);
    }

    /// <summary>
    /// Re-runs key exchange on an established connection (RFC 4253 §9 rekeying), deriving fresh keys
    /// and swapping in new ciphers while preserving the original session identifier. The caller (the
    /// connection layer) is responsible for deciding <em>when</em> to rekey and for not interleaving
    /// application data with the rekey exchange.
    /// </summary>
    /// <param name="sessionId">The session identifier established by the first exchange.</param>
    /// <param name="packetSource">
    /// The source of inbound key-exchange packets. When re-keying under a connection's receive loop the
    /// connection supplies an <see cref="SshPacketQueue"/> it feeds from the loop (the loop stays the
    /// sole reader of the transport); pass <see langword="null"/> to read the transport directly.
    /// </param>
    /// <param name="cancellationToken">Cancels the exchange.</param>
    /// <returns>The renegotiated algorithms, verified host key, and freshly derived session keys.</returns>
    /// <exception cref="ArgumentNullException">The session id is null.</exception>
    /// <exception cref="SshKeyExchangeException">Negotiation failed, a message was malformed, or the host-key signature did not verify.</exception>
    public ValueTask<SshKeyExchangeResult> RekeyAsync(byte[] sessionId, ISshPacketSource? packetSource = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(sessionId);
        return ExecuteAsync(sessionId, packetSource ?? _transport, cancellationToken);
    }

    private async ValueTask<SshKeyExchangeResult> ExecuteAsync(byte[]? existingSessionId, ISshPacketSource packetSource, CancellationToken cancellationToken)
    {
        using Activity? activity = SshActivitySource.Instance.StartActivity("ssh.key_exchange");

        SshVersionExchangeResult version = _transport.VersionExchange;

        byte[] clientKexInitPayload = SerializeLocalKexInit();
        await _transport.SendPacketAsync(clientKexInitPayload, cancellationToken).ConfigureAwait(false);

        byte[] serverKexInitPayload = await ReceivePayloadAsync(packetSource, SshMessageNumber.KexInit, cancellationToken).ConfigureAwait(false);
        SshKexInit clientKexInit = SshKexInit.Parse(clientKexInitPayload);
        SshKexInit serverKexInit = SshKexInit.Parse(serverKexInitPayload);
        SshNegotiatedAlgorithms algorithms = SshAlgorithmNegotiation.Negotiate(clientKexInit, serverKexInit);

        if (_logger.IsEnabled(SshLogLevel.Information))
        {
            _logger.Log(SshLogLevel.Information, "Negotiated kex={0}, host key={1}, cipher c2s={2}.",
                algorithms.KeyExchange, algorithms.ServerHostKey, algorithms.EncryptionClientToServer);
        }

        ISshKeyExchangeAlgorithm algorithm = SshKeyExchangeAlgorithmFactory.Create(algorithms.KeyExchange, _random);
        byte[] clientPublicValue = algorithm.CreateClientPublicValue();
        await SendKexInitiationAsync(clientPublicValue, algorithm.PublicValueFormat, cancellationToken).ConfigureAwait(false);

        SshKeyExchangeReply reply = await ReceiveKexReplyAsync(packetSource, algorithm.PublicValueFormat, cancellationToken).ConfigureAwait(false);

        byte[] sharedSecret = algorithm.DeriveSharedSecret(reply.ServerPublicValue);
        byte[] exchangeHash = SshExchangeHash.Compute(
            algorithm.HashAlgorithm,
            version.LocalRawBytes,
            version.RemoteRawBytes,
            clientKexInitPayload,
            serverKexInitPayload,
            reply.HostKeyBlob,
            clientPublicValue,
            reply.ServerPublicValue,
            algorithm.PublicValueFormat,
            sharedSecret);

        ISshHostKey hostKey = SshHostKeyParser.Parse(reply.HostKeyBlob);
        if (!hostKey.Verify(exchangeHash, reply.Signature))
        {
            throw new SshKeyExchangeException(
                $"The server host-key signature did not verify (host key {hostKey.Algorithm}, fingerprint {hostKey.Fingerprint}).");
        }

        await ExchangeNewKeysAsync(packetSource, cancellationToken).ConfigureAwait(false);

        SshSessionKeys sessionKeys = DeriveSessionKeys(algorithm.HashAlgorithm, sharedSecret, exchangeHash, existingSessionId);
        ActivateCiphers(algorithms, sessionKeys);
        if (_logger.IsEnabled(SshLogLevel.Information))
        {
            _logger.Log(SshLogLevel.Information, "Key exchange complete; host key fingerprint {0}.", hostKey.Fingerprint);
        }
        return new SshKeyExchangeResult(algorithms, hostKey, exchangeHash, sessionKeys);
    }

    private void ActivateCiphers(SshNegotiatedAlgorithms algorithms, SshSessionKeys sessionKeys)
    {
        // Client role: outbound is client-to-server, inbound is server-to-client.
        ISshPacketCipher outbound = SshCipherFactory.Create(
            algorithms.EncryptionClientToServer,
            algorithms.MacClientToServer,
            sessionKeys.EncryptionKeyClientToServer,
            sessionKeys.InitialIvClientToServer,
            sessionKeys.IntegrityKeyClientToServer);
        ISshPacketCipher inbound = SshCipherFactory.Create(
            algorithms.EncryptionServerToClient,
            algorithms.MacServerToClient,
            sessionKeys.EncryptionKeyServerToClient,
            sessionKeys.InitialIvServerToClient,
            sessionKeys.IntegrityKeyServerToClient);
        _transport.ApplyKeys(inbound, outbound);
    }

    private byte[] SerializeLocalKexInit()
    {
        SshKexInit local = SshKexInit.CreateLocal(_catalog, _random);
        using PooledBufferWriter writer = new PooledBufferWriter(256);
        local.WritePayload(writer);
        return writer.WrittenSpan.ToArray();
    }

    private async ValueTask SendKexInitiationAsync(byte[] publicValue, SshKeyExchangePublicValueFormat format, CancellationToken cancellationToken)
    {
        using PooledBufferWriter writer = new PooledBufferWriter(publicValue.Length + 8);
        SshWireWriter wire = new SshWireWriter(writer);
        wire.WriteByte((byte)SshMessageNumber.KexExchangeSpecific30);
        WritePublicValue(ref wire, publicValue, format);
        await _transport.SendPacketAsync(writer.WrittenMemory, cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask<SshKeyExchangeReply> ReceiveKexReplyAsync(ISshPacketSource packetSource, SshKeyExchangePublicValueFormat format, CancellationToken cancellationToken)
    {
        byte[] payload = await ReceivePayloadAsync(packetSource, SshMessageNumber.KexExchangeSpecific31, cancellationToken).ConfigureAwait(false);
        try
        {
            SshWireReader reader = new SshWireReader(payload);
            reader.ReadByte();
            byte[] hostKeyBlob = reader.ReadString().ToArray();
            byte[] serverPublicValue = format == SshKeyExchangePublicValueFormat.MultiPrecisionInteger
                ? reader.ReadMultiPrecisionIntegerMagnitude().ToArray()
                : reader.ReadString().ToArray();
            byte[] signature = reader.ReadString().ToArray();
            return new SshKeyExchangeReply(hostKeyBlob, serverPublicValue, signature);
        }
        catch (SshWireFormatException exception)
        {
            throw new SshKeyExchangeException("The key-exchange reply was malformed.", SshDisconnectReason.KeyExchangeFailed, exception);
        }
    }

    private async ValueTask ExchangeNewKeysAsync(ISshPacketSource packetSource, CancellationToken cancellationToken)
    {
        byte[] newKeys = new byte[] { (byte)SshMessageNumber.NewKeys };
        await _transport.SendPacketAsync(newKeys, cancellationToken).ConfigureAwait(false);
        byte[] serverNewKeys = await ReceivePayloadAsync(packetSource, SshMessageNumber.NewKeys, cancellationToken).ConfigureAwait(false);
        if (serverNewKeys.Length != 1)
        {
            throw new SshKeyExchangeException("The SSH_MSG_NEWKEYS message carried unexpected data.");
        }
    }

    private SshSessionKeys DeriveSessionKeys(System.Security.Cryptography.HashAlgorithmName hashAlgorithm, byte[] sharedSecret, byte[] exchangeHash, byte[]? existingSessionId)
    {
        // First exchange: session id is the exchange hash. Rekey: the original session id is preserved
        // (RFC 4253 §7.2) while the derivation still binds to the new exchange hash and shared secret.
        byte[] sessionId = existingSessionId ?? exchangeHash;
        return new SshSessionKeys(
            sessionId,
            SshKeyDerivation.DeriveKey(hashAlgorithm, sharedSecret, exchangeHash, SshKeyDerivation.InitialIvClientToServer, sessionId, DerivedKeyLength),
            SshKeyDerivation.DeriveKey(hashAlgorithm, sharedSecret, exchangeHash, SshKeyDerivation.InitialIvServerToClient, sessionId, DerivedKeyLength),
            SshKeyDerivation.DeriveKey(hashAlgorithm, sharedSecret, exchangeHash, SshKeyDerivation.EncryptionKeyClientToServer, sessionId, DerivedKeyLength),
            SshKeyDerivation.DeriveKey(hashAlgorithm, sharedSecret, exchangeHash, SshKeyDerivation.EncryptionKeyServerToClient, sessionId, DerivedKeyLength),
            SshKeyDerivation.DeriveKey(hashAlgorithm, sharedSecret, exchangeHash, SshKeyDerivation.IntegrityKeyClientToServer, sessionId, DerivedKeyLength),
            SshKeyDerivation.DeriveKey(hashAlgorithm, sharedSecret, exchangeHash, SshKeyDerivation.IntegrityKeyServerToClient, sessionId, DerivedKeyLength));
    }

    private static async ValueTask<byte[]> ReceivePayloadAsync(ISshPacketSource packetSource, SshMessageNumber expected, CancellationToken cancellationToken)
    {
        using SshIncomingPacket packet = await packetSource.ReceivePacketAsync(cancellationToken).ConfigureAwait(false);
        if (packet.IsEmpty || packet.MessageNumber != (byte)expected)
        {
            byte actual = packet.IsEmpty ? (byte)0 : packet.MessageNumber;
            throw new SshKeyExchangeException($"Expected SSH message {(byte)expected} but received {actual} during key exchange.");
        }
        return packet.Payload.ToArray();
    }

    private static void WritePublicValue(ref SshWireWriter writer, ReadOnlySpan<byte> value, SshKeyExchangePublicValueFormat format)
    {
        if (format == SshKeyExchangePublicValueFormat.MultiPrecisionInteger)
        {
            writer.WriteMultiPrecisionInteger(value);
        }
        else
        {
            writer.WriteString(value);
        }
    }

    private readonly struct SshKeyExchangeReply
    {
        public SshKeyExchangeReply(byte[] hostKeyBlob, byte[] serverPublicValue, byte[] signature)
        {
            HostKeyBlob = hostKeyBlob;
            ServerPublicValue = serverPublicValue;
            Signature = signature;
        }

        public byte[] HostKeyBlob { get; }

        public byte[] ServerPublicValue { get; }

        public byte[] Signature { get; }
    }
}
