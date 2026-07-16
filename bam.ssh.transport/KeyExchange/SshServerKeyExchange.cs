using System.Diagnostics;

namespace Bam.Ssh.Transport;

/// <summary>
/// Drives the server role of an SSH key exchange over an <see cref="SshTransport"/> (RFC 4253 §7): sends
/// the local KEXINIT, negotiates algorithms against the client's, runs the chosen key agreement using the
/// client's public value, computes the exchange hash, <em>signs</em> it with the server host key, replies,
/// and exchanges SSH_MSG_NEWKEYS. On success it activates the server-role ciphers (inbound = client→server,
/// outbound = server→client) and produces the negotiated algorithms and derived
/// <see cref="SshSessionKeys"/>. The structural mirror of <see cref="SshClientKeyExchange"/>.
/// </summary>
public sealed class SshServerKeyExchange : ISshRekeyDriver
{
    private const int DerivedKeyLength = 64;

    private readonly SshTransport _transport;
    private readonly IReadOnlyList<ISshHostKeySigner> _hostKeys;
    private readonly SshAlgorithmCatalog _catalog;
    private readonly ISshRandom _random;
    private readonly ISshLogger _logger;

    /// <summary>
    /// Initializes the server key exchange.
    /// </summary>
    /// <param name="transport">The connected transport (version exchange must have completed).</param>
    /// <param name="hostKeys">The server host keys; the one matching the negotiated algorithm signs.</param>
    /// <param name="catalog">
    /// The local algorithm catalog; when null, one is derived from <see cref="SshAlgorithmCatalog.Default"/>
    /// with the host-key list restricted to the algorithms of <paramref name="hostKeys"/> so negotiation
    /// only ever picks a key this server holds.
    /// </param>
    /// <param name="random">The randomness source; defaults to <see cref="SecureSshRandom.Instance"/>.</param>
    /// <param name="logger">The logger; defaults to <see cref="NullSshLogger.Instance"/>.</param>
    /// <exception cref="ArgumentNullException">The transport or host keys are null.</exception>
    /// <exception cref="ArgumentException">No host keys were supplied.</exception>
    public SshServerKeyExchange(
        SshTransport transport,
        IReadOnlyList<ISshHostKeySigner> hostKeys,
        SshAlgorithmCatalog? catalog = null,
        ISshRandom? random = null,
        ISshLogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(hostKeys);
        if (hostKeys.Count == 0)
        {
            throw new ArgumentException("At least one host key is required.", nameof(hostKeys));
        }
        _transport = transport;
        _hostKeys = hostKeys;
        _catalog = catalog ?? BuildCatalog(hostKeys);
        _random = random ?? SecureSshRandom.Instance;
        _logger = logger ?? NullSshLogger.Instance;
    }

    private static SshAlgorithmCatalog BuildCatalog(IReadOnlyList<ISshHostKeySigner> hostKeys)
    {
        SshAlgorithmCatalog baseline = SshAlgorithmCatalog.Default;
        string[] hostKeyAlgorithms = new string[hostKeys.Count];
        for (int i = 0; i < hostKeys.Count; i++)
        {
            hostKeyAlgorithms[i] = hostKeys[i].Algorithm;
        }
        return new SshAlgorithmCatalog(
            baseline.KeyExchange,
            new SshNameList(hostKeyAlgorithms),
            baseline.Encryption,
            baseline.Mac,
            baseline.Compression);
    }

    private ISshHostKeySigner SelectHostKey(string algorithm)
    {
        foreach (ISshHostKeySigner hostKey in _hostKeys)
        {
            if (string.Equals(hostKey.Algorithm, algorithm, StringComparison.Ordinal))
            {
                return hostKey;
            }
        }
        throw new SshKeyExchangeException($"No server host key matches the negotiated algorithm '{algorithm}'.");
    }

    /// <summary>
    /// Performs the full server-side initial key exchange and activates the negotiated ciphers.
    /// </summary>
    /// <param name="cancellationToken">Cancels the exchange.</param>
    /// <returns>The negotiated algorithms, host key, exchange hash, and derived session keys.</returns>
    /// <exception cref="SshKeyExchangeException">Negotiation failed or a message was malformed.</exception>
    public ValueTask<SshKeyExchangeResult> PerformAsync(CancellationToken cancellationToken = default)
    {
        return ExecuteAsync(existingSessionId: null, _transport, cancellationToken);
    }

    /// <inheritdoc/>
    public ValueTask<SshKeyExchangeResult> RekeyAsync(byte[] sessionId, ISshPacketSource? packetSource = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(sessionId);
        return ExecuteAsync(sessionId, packetSource ?? _transport, cancellationToken);
    }

    private async ValueTask<SshKeyExchangeResult> ExecuteAsync(byte[]? existingSessionId, ISshPacketSource packetSource, CancellationToken cancellationToken)
    {
        using Activity? activity = SshActivitySource.Instance.StartActivity("ssh.key_exchange.server");

        SshVersionExchangeResult version = _transport.VersionExchange;

        byte[] serverKexInitPayload = SerializeLocalKexInit();
        await _transport.SendPacketAsync(serverKexInitPayload, cancellationToken).ConfigureAwait(false);

        byte[] clientKexInitPayload = await ReceivePayloadAsync(packetSource, SshMessageNumber.KexInit, cancellationToken).ConfigureAwait(false);
        SshNegotiatedAlgorithms algorithms = SshAlgorithmNegotiation.Negotiate(
            SshKexInit.Parse(clientKexInitPayload), SshKexInit.Parse(serverKexInitPayload));

        if (_logger.IsEnabled(SshLogLevel.Information))
        {
            _logger.Log(SshLogLevel.Information, "Server negotiated kex={0}, host key={1}, cipher c2s={2}.",
                algorithms.KeyExchange, algorithms.ServerHostKey, algorithms.EncryptionClientToServer);
        }

        ISshHostKeySigner selectedHostKey = SelectHostKey(algorithms.ServerHostKey);

        ISshKeyExchangeAlgorithm algorithm = SshKeyExchangeAlgorithmFactory.Create(algorithms.KeyExchange, _random);
        byte[] clientPublicValue = await ReceiveKexInitiationAsync(packetSource, algorithm.PublicValueFormat, cancellationToken).ConfigureAwait(false);

        byte[] serverPublicValue = algorithm.CreateClientPublicValue();
        byte[] sharedSecret = algorithm.DeriveSharedSecret(clientPublicValue);
        byte[] hostKeyBlob = selectedHostKey.PublicKeyBlob.ToArray();

        byte[] exchangeHash = SshExchangeHash.Compute(
            algorithm.HashAlgorithm,
            version.RemoteRawBytes,
            version.LocalRawBytes,
            clientKexInitPayload,
            serverKexInitPayload,
            hostKeyBlob,
            clientPublicValue,
            serverPublicValue,
            algorithm.PublicValueFormat,
            sharedSecret);

        byte[] signature = selectedHostKey.Sign(exchangeHash);
        await SendKexReplyAsync(hostKeyBlob, serverPublicValue, signature, algorithm.PublicValueFormat, cancellationToken).ConfigureAwait(false);

        await ExchangeNewKeysAsync(packetSource, cancellationToken).ConfigureAwait(false);

        SshSessionKeys sessionKeys = DeriveSessionKeys(algorithm.HashAlgorithm, sharedSecret, exchangeHash, existingSessionId);
        ActivateCiphers(algorithms, sessionKeys);
        ISshHostKey hostKey = SshHostKeyParser.Parse(hostKeyBlob);
        if (_logger.IsEnabled(SshLogLevel.Information))
        {
            _logger.Log(SshLogLevel.Information, "Server key exchange complete; host key fingerprint {0}.", hostKey.Fingerprint);
        }
        return new SshKeyExchangeResult(algorithms, hostKey, exchangeHash, sessionKeys);
    }

    private void ActivateCiphers(SshNegotiatedAlgorithms algorithms, SshSessionKeys sessionKeys)
    {
        // Server role: inbound is client-to-server, outbound is server-to-client.
        ISshPacketCipher inbound = SshCipherFactory.Create(
            algorithms.EncryptionClientToServer,
            algorithms.MacClientToServer,
            sessionKeys.EncryptionKeyClientToServer,
            sessionKeys.InitialIvClientToServer,
            sessionKeys.IntegrityKeyClientToServer);
        ISshPacketCipher outbound = SshCipherFactory.Create(
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

    private async ValueTask<byte[]> ReceiveKexInitiationAsync(ISshPacketSource packetSource, SshKeyExchangePublicValueFormat format, CancellationToken cancellationToken)
    {
        byte[] payload = await ReceivePayloadAsync(packetSource, SshMessageNumber.KexExchangeSpecific30, cancellationToken).ConfigureAwait(false);
        try
        {
            SshWireReader reader = new SshWireReader(payload);
            reader.ReadByte();
            return format == SshKeyExchangePublicValueFormat.MultiPrecisionInteger
                ? reader.ReadMultiPrecisionIntegerMagnitude().ToArray()
                : reader.ReadString().ToArray();
        }
        catch (SshWireFormatException exception)
        {
            throw new SshKeyExchangeException("The client key-exchange initiation was malformed.", SshDisconnectReason.KeyExchangeFailed, exception);
        }
    }

    private async ValueTask SendKexReplyAsync(byte[] hostKeyBlob, byte[] serverPublicValue, byte[] signature, SshKeyExchangePublicValueFormat format, CancellationToken cancellationToken)
    {
        using PooledBufferWriter writer = new PooledBufferWriter(256);
        SshWireWriter wire = new SshWireWriter(writer);
        wire.WriteByte((byte)SshMessageNumber.KexExchangeSpecific31);
        wire.WriteString(hostKeyBlob);
        if (format == SshKeyExchangePublicValueFormat.MultiPrecisionInteger)
        {
            wire.WriteMultiPrecisionInteger(serverPublicValue);
        }
        else
        {
            wire.WriteString(serverPublicValue);
        }
        wire.WriteString(signature);
        await _transport.SendPacketAsync(writer.WrittenMemory, cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask ExchangeNewKeysAsync(ISshPacketSource packetSource, CancellationToken cancellationToken)
    {
        byte[] clientNewKeys = await ReceivePayloadAsync(packetSource, SshMessageNumber.NewKeys, cancellationToken).ConfigureAwait(false);
        if (clientNewKeys.Length != 1)
        {
            throw new SshKeyExchangeException("The SSH_MSG_NEWKEYS message carried unexpected data.");
        }
        byte[] serverNewKeys = new byte[] { (byte)SshMessageNumber.NewKeys };
        await _transport.SendPacketAsync(serverNewKeys, cancellationToken).ConfigureAwait(false);
    }

    private SshSessionKeys DeriveSessionKeys(System.Security.Cryptography.HashAlgorithmName hashAlgorithm, byte[] sharedSecret, byte[] exchangeHash, byte[]? existingSessionId)
    {
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
            throw new SshKeyExchangeException($"Expected SSH message {(byte)expected} but received {actual} during server key exchange.");
        }
        return packet.Payload.ToArray();
    }
}
