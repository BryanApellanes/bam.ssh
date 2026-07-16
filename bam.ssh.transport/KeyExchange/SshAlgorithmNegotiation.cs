namespace Bam.Ssh.Transport;

/// <summary>
/// Applies the RFC 4253 §7.1 algorithm-negotiation rules to a client and server KEXINIT. For each
/// category the guide is the *client's* list: the negotiated algorithm is the first client-preferred
/// name that the server also offers. Key exchange and host key are negotiated jointly (the chosen
/// host-key algorithm must be usable with the chosen kex — for the required methods any host key
/// works, so the standard first-match rule applies); ciphers, MACs, and compression are negotiated
/// independently per direction.
/// </summary>
public static class SshAlgorithmNegotiation
{
    /// <summary>
    /// Negotiates the session algorithms from both parties' KEXINIT messages.
    /// </summary>
    /// <param name="clientKexInit">The client's KEXINIT.</param>
    /// <param name="serverKexInit">The server's KEXINIT.</param>
    /// <returns>The negotiated algorithm in every category.</returns>
    /// <exception cref="SshKeyExchangeException">No algorithm is common to both parties in some category.</exception>
    public static SshNegotiatedAlgorithms Negotiate(SshKexInit clientKexInit, SshKexInit serverKexInit)
    {
        ArgumentNullException.ThrowIfNull(clientKexInit);
        ArgumentNullException.ThrowIfNull(serverKexInit);

        string keyExchange = Choose("key exchange", clientKexInit.KeyExchangeAlgorithms, serverKexInit.KeyExchangeAlgorithms);
        string serverHostKey = Choose("server host key", clientKexInit.ServerHostKeyAlgorithms, serverKexInit.ServerHostKeyAlgorithms);
        string encryptionClientToServer = Choose("client-to-server encryption", clientKexInit.EncryptionClientToServer, serverKexInit.EncryptionClientToServer);
        string encryptionServerToClient = Choose("server-to-client encryption", clientKexInit.EncryptionServerToClient, serverKexInit.EncryptionServerToClient);
        string macClientToServer = Choose("client-to-server MAC", clientKexInit.MacClientToServer, serverKexInit.MacClientToServer);
        string macServerToClient = Choose("server-to-client MAC", clientKexInit.MacServerToClient, serverKexInit.MacServerToClient);
        string compressionClientToServer = Choose("client-to-server compression", clientKexInit.CompressionClientToServer, serverKexInit.CompressionClientToServer);
        string compressionServerToClient = Choose("server-to-client compression", clientKexInit.CompressionServerToClient, serverKexInit.CompressionServerToClient);

        return new SshNegotiatedAlgorithms(
            keyExchange, serverHostKey,
            encryptionClientToServer, encryptionServerToClient,
            macClientToServer, macServerToClient,
            compressionClientToServer, compressionServerToClient);
    }

    private static string Choose(string category, SshNameList clientList, SshNameList serverList)
    {
        if (clientList.TryFindFirstCommon(serverList, out string match))
        {
            return match;
        }
        throw new SshKeyExchangeException(
            $"No common {category} algorithm. Client offered [{clientList}], server offered [{serverList}].");
    }
}
