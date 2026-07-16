namespace Bam.Ssh.Transport;

/// <summary>
/// The directional key material derived from a key exchange (RFC 4253 §7.2): initial IVs, encryption
/// keys, and integrity (MAC) keys for each direction, plus the session identifier. Phase 4 consumes
/// these to construct the live ciphers and MACs it installs via <see cref="SshTransport.ApplyKeys"/>.
/// The arrays are full-length digest outputs; each cipher takes the prefix it needs.
/// </summary>
public sealed class SshSessionKeys
{
    /// <summary>
    /// Initializes the derived key material.
    /// </summary>
    /// <param name="sessionId">The session identifier (H of the first key exchange).</param>
    /// <param name="initialIvClientToServer">Initial IV for the client-to-server direction.</param>
    /// <param name="initialIvServerToClient">Initial IV for the server-to-client direction.</param>
    /// <param name="encryptionKeyClientToServer">Encryption key for the client-to-server direction.</param>
    /// <param name="encryptionKeyServerToClient">Encryption key for the server-to-client direction.</param>
    /// <param name="integrityKeyClientToServer">Integrity (MAC) key for the client-to-server direction.</param>
    /// <param name="integrityKeyServerToClient">Integrity (MAC) key for the server-to-client direction.</param>
    public SshSessionKeys(
        byte[] sessionId,
        byte[] initialIvClientToServer,
        byte[] initialIvServerToClient,
        byte[] encryptionKeyClientToServer,
        byte[] encryptionKeyServerToClient,
        byte[] integrityKeyClientToServer,
        byte[] integrityKeyServerToClient)
    {
        SessionId = sessionId;
        InitialIvClientToServer = initialIvClientToServer;
        InitialIvServerToClient = initialIvServerToClient;
        EncryptionKeyClientToServer = encryptionKeyClientToServer;
        EncryptionKeyServerToClient = encryptionKeyServerToClient;
        IntegrityKeyClientToServer = integrityKeyClientToServer;
        IntegrityKeyServerToClient = integrityKeyServerToClient;
    }

    /// <summary>Gets the session identifier (H of the first key exchange), stable for the connection's life.</summary>
    public byte[] SessionId { get; }

    /// <summary>Gets the initial IV for the client-to-server direction (letter A).</summary>
    public byte[] InitialIvClientToServer { get; }

    /// <summary>Gets the initial IV for the server-to-client direction (letter B).</summary>
    public byte[] InitialIvServerToClient { get; }

    /// <summary>Gets the encryption key for the client-to-server direction (letter C).</summary>
    public byte[] EncryptionKeyClientToServer { get; }

    /// <summary>Gets the encryption key for the server-to-client direction (letter D).</summary>
    public byte[] EncryptionKeyServerToClient { get; }

    /// <summary>Gets the integrity (MAC) key for the client-to-server direction (letter E).</summary>
    public byte[] IntegrityKeyClientToServer { get; }

    /// <summary>Gets the integrity (MAC) key for the server-to-client direction (letter F).</summary>
    public byte[] IntegrityKeyServerToClient { get; }
}
