namespace Bam.Ssh.Transport;

/// <summary>
/// The algorithms chosen for a session after RFC 4253 §7.1 negotiation: one key-exchange method,
/// one host-key algorithm, and a cipher / MAC / compression algorithm for each direction.
/// </summary>
public readonly struct SshNegotiatedAlgorithms
{
    /// <summary>
    /// Initializes the negotiated result.
    /// </summary>
    /// <param name="keyExchange">The chosen key-exchange algorithm.</param>
    /// <param name="serverHostKey">The chosen host-key algorithm.</param>
    /// <param name="encryptionClientToServer">The chosen client-to-server cipher.</param>
    /// <param name="encryptionServerToClient">The chosen server-to-client cipher.</param>
    /// <param name="macClientToServer">The chosen client-to-server MAC.</param>
    /// <param name="macServerToClient">The chosen server-to-client MAC.</param>
    /// <param name="compressionClientToServer">The chosen client-to-server compression.</param>
    /// <param name="compressionServerToClient">The chosen server-to-client compression.</param>
    public SshNegotiatedAlgorithms(
        string keyExchange,
        string serverHostKey,
        string encryptionClientToServer,
        string encryptionServerToClient,
        string macClientToServer,
        string macServerToClient,
        string compressionClientToServer,
        string compressionServerToClient)
    {
        KeyExchange = keyExchange;
        ServerHostKey = serverHostKey;
        EncryptionClientToServer = encryptionClientToServer;
        EncryptionServerToClient = encryptionServerToClient;
        MacClientToServer = macClientToServer;
        MacServerToClient = macServerToClient;
        CompressionClientToServer = compressionClientToServer;
        CompressionServerToClient = compressionServerToClient;
    }

    /// <summary>Gets the negotiated key-exchange algorithm.</summary>
    public string KeyExchange { get; }

    /// <summary>Gets the negotiated host-key algorithm.</summary>
    public string ServerHostKey { get; }

    /// <summary>Gets the negotiated client-to-server cipher.</summary>
    public string EncryptionClientToServer { get; }

    /// <summary>Gets the negotiated server-to-client cipher.</summary>
    public string EncryptionServerToClient { get; }

    /// <summary>Gets the negotiated client-to-server MAC.</summary>
    public string MacClientToServer { get; }

    /// <summary>Gets the negotiated server-to-client MAC.</summary>
    public string MacServerToClient { get; }

    /// <summary>Gets the negotiated client-to-server compression.</summary>
    public string CompressionClientToServer { get; }

    /// <summary>Gets the negotiated server-to-client compression.</summary>
    public string CompressionServerToClient { get; }
}
