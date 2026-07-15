namespace Bam.Ssh.Transport;

/// <summary>
/// The outcome of the RFC 4253 §4.2 identification exchange: both parties' identification strings
/// and their exact raw line bytes (without the trailing CRLF). The raw bytes are retained because
/// key exchange (Phase 3) feeds them, unmodified, into the exchange hash H that binds the handshake.
/// </summary>
public readonly struct SshVersionExchangeResult
{
    /// <summary>
    /// Initializes an exchange result.
    /// </summary>
    /// <param name="local">This side's identification string.</param>
    /// <param name="remote">The peer's identification string.</param>
    /// <param name="localRawBytes">This side's identification line bytes, excluding CRLF.</param>
    /// <param name="remoteRawBytes">The peer's identification line bytes, excluding CRLF.</param>
    public SshVersionExchangeResult(
        SshIdentificationString local,
        SshIdentificationString remote,
        byte[] localRawBytes,
        byte[] remoteRawBytes)
    {
        Local = local;
        Remote = remote;
        LocalRawBytes = localRawBytes;
        RemoteRawBytes = remoteRawBytes;
    }

    /// <summary>
    /// Gets this side's identification string.
    /// </summary>
    public SshIdentificationString Local { get; }

    /// <summary>
    /// Gets the peer's identification string.
    /// </summary>
    public SshIdentificationString Remote { get; }

    /// <summary>
    /// Gets this side's identification line bytes without CRLF, as fed into the exchange hash.
    /// </summary>
    public byte[] LocalRawBytes { get; }

    /// <summary>
    /// Gets the peer's identification line bytes without CRLF, as fed into the exchange hash.
    /// </summary>
    public byte[] RemoteRawBytes { get; }
}
