using System.Buffers;

namespace Bam.Ssh.Transport;

/// <summary>
/// The SSH_MSG_KEXINIT message (RFC 4253 §7.1): a 16-byte random cookie, ten algorithm name-lists
/// (key exchange; server host key; encryption client-to-server and server-to-client; MAC each
/// direction; compression each direction; languages each direction), a <c>first_kex_packet_follows</c>
/// boolean, and a reserved uint32. The exact serialized payload — including the leading message
/// number byte — is what feeds the exchange hash as I_C / I_S, so the orchestrator keeps the wire
/// bytes it sent and received rather than re-serializing.
/// </summary>
public sealed class SshKexInit
{
    /// <summary>The fixed length of the KEXINIT cookie in bytes.</summary>
    public const int CookieLength = 16;

    /// <summary>
    /// Initializes a KEXINIT from its components.
    /// </summary>
    /// <param name="cookie">The 16-byte random cookie.</param>
    /// <param name="keyExchangeAlgorithms">Key-exchange algorithm name-list.</param>
    /// <param name="serverHostKeyAlgorithms">Server host-key algorithm name-list.</param>
    /// <param name="encryptionClientToServer">Client-to-server encryption name-list.</param>
    /// <param name="encryptionServerToClient">Server-to-client encryption name-list.</param>
    /// <param name="macClientToServer">Client-to-server MAC name-list.</param>
    /// <param name="macServerToClient">Server-to-client MAC name-list.</param>
    /// <param name="compressionClientToServer">Client-to-server compression name-list.</param>
    /// <param name="compressionServerToClient">Server-to-client compression name-list.</param>
    /// <param name="languagesClientToServer">Client-to-server languages name-list.</param>
    /// <param name="languagesServerToClient">Server-to-client languages name-list.</param>
    /// <param name="firstKexPacketFollows">Whether a guessed key-exchange packet follows.</param>
    /// <exception cref="ArgumentException">The cookie is not exactly 16 bytes.</exception>
    public SshKexInit(
        ReadOnlyMemory<byte> cookie,
        SshNameList keyExchangeAlgorithms,
        SshNameList serverHostKeyAlgorithms,
        SshNameList encryptionClientToServer,
        SshNameList encryptionServerToClient,
        SshNameList macClientToServer,
        SshNameList macServerToClient,
        SshNameList compressionClientToServer,
        SshNameList compressionServerToClient,
        SshNameList languagesClientToServer = default,
        SshNameList languagesServerToClient = default,
        bool firstKexPacketFollows = false)
    {
        if (cookie.Length != CookieLength)
        {
            throw new ArgumentException($"The KEXINIT cookie must be exactly {CookieLength} bytes.", nameof(cookie));
        }
        Cookie = cookie;
        KeyExchangeAlgorithms = keyExchangeAlgorithms;
        ServerHostKeyAlgorithms = serverHostKeyAlgorithms;
        EncryptionClientToServer = encryptionClientToServer;
        EncryptionServerToClient = encryptionServerToClient;
        MacClientToServer = macClientToServer;
        MacServerToClient = macServerToClient;
        CompressionClientToServer = compressionClientToServer;
        CompressionServerToClient = compressionServerToClient;
        LanguagesClientToServer = languagesClientToServer;
        LanguagesServerToClient = languagesServerToClient;
        FirstKexPacketFollows = firstKexPacketFollows;
    }

    /// <summary>Gets the 16-byte random cookie.</summary>
    public ReadOnlyMemory<byte> Cookie { get; }

    /// <summary>Gets the key-exchange algorithm name-list.</summary>
    public SshNameList KeyExchangeAlgorithms { get; }

    /// <summary>Gets the server host-key algorithm name-list.</summary>
    public SshNameList ServerHostKeyAlgorithms { get; }

    /// <summary>Gets the client-to-server encryption name-list.</summary>
    public SshNameList EncryptionClientToServer { get; }

    /// <summary>Gets the server-to-client encryption name-list.</summary>
    public SshNameList EncryptionServerToClient { get; }

    /// <summary>Gets the client-to-server MAC name-list.</summary>
    public SshNameList MacClientToServer { get; }

    /// <summary>Gets the server-to-client MAC name-list.</summary>
    public SshNameList MacServerToClient { get; }

    /// <summary>Gets the client-to-server compression name-list.</summary>
    public SshNameList CompressionClientToServer { get; }

    /// <summary>Gets the server-to-client compression name-list.</summary>
    public SshNameList CompressionServerToClient { get; }

    /// <summary>Gets the client-to-server languages name-list.</summary>
    public SshNameList LanguagesClientToServer { get; }

    /// <summary>Gets the server-to-client languages name-list.</summary>
    public SshNameList LanguagesServerToClient { get; }

    /// <summary>Gets whether a guessed key-exchange packet follows this message.</summary>
    public bool FirstKexPacketFollows { get; }

    /// <summary>
    /// Builds a local KEXINIT from a catalog, generating a fresh random cookie. bam.ssh never sends a
    /// speculative guess, so <c>first_kex_packet_follows</c> is false.
    /// </summary>
    /// <param name="catalog">The locally supported algorithms.</param>
    /// <param name="random">The randomness source for the cookie.</param>
    /// <returns>A KEXINIT advertising the catalog's algorithms.</returns>
    public static SshKexInit CreateLocal(SshAlgorithmCatalog catalog, ISshRandom random)
    {
        ArgumentNullException.ThrowIfNull(catalog);
        ArgumentNullException.ThrowIfNull(random);
        byte[] cookie = new byte[CookieLength];
        random.Fill(cookie);
        return new SshKexInit(
            cookie,
            catalog.KeyExchange,
            catalog.ServerHostKey,
            catalog.Encryption,
            catalog.Encryption,
            catalog.Mac,
            catalog.Mac,
            catalog.Compression,
            catalog.Compression,
            SshNameList.Empty,
            SshNameList.Empty,
            firstKexPacketFollows: false);
    }

    /// <summary>
    /// Serializes this KEXINIT as a complete packet payload (leading SSH_MSG_KEXINIT byte included),
    /// which is exactly the form fed to the exchange hash as I_C / I_S.
    /// </summary>
    /// <param name="output">The buffer writer to serialize into.</param>
    public void WritePayload(IBufferWriter<byte> output)
    {
        ArgumentNullException.ThrowIfNull(output);
        SshWireWriter writer = new SshWireWriter(output);
        writer.WriteByte((byte)SshMessageNumber.KexInit);
        writer.WriteRaw(Cookie.Span);
        writer.WriteNameList(KeyExchangeAlgorithms);
        writer.WriteNameList(ServerHostKeyAlgorithms);
        writer.WriteNameList(EncryptionClientToServer);
        writer.WriteNameList(EncryptionServerToClient);
        writer.WriteNameList(MacClientToServer);
        writer.WriteNameList(MacServerToClient);
        writer.WriteNameList(CompressionClientToServer);
        writer.WriteNameList(CompressionServerToClient);
        writer.WriteNameList(LanguagesClientToServer);
        writer.WriteNameList(LanguagesServerToClient);
        writer.WriteBoolean(FirstKexPacketFollows);
        writer.WriteUInt32(0);
    }

    /// <summary>
    /// Parses a KEXINIT from a complete packet payload (including the leading message-number byte).
    /// </summary>
    /// <param name="payload">The KEXINIT payload bytes.</param>
    /// <returns>The parsed message.</returns>
    /// <exception cref="SshKeyExchangeException">The payload is not a well-formed KEXINIT.</exception>
    public static SshKexInit Parse(ReadOnlySpan<byte> payload)
    {
        try
        {
            SshWireReader reader = new SshWireReader(payload);
            byte messageNumber = reader.ReadByte();
            if (messageNumber != (byte)SshMessageNumber.KexInit)
            {
                throw new SshKeyExchangeException($"Expected SSH_MSG_KEXINIT (20) but received message {messageNumber}.");
            }
            byte[] cookie = reader.ReadRaw(CookieLength).ToArray();
            SshNameList kex = reader.ReadNameList();
            SshNameList hostKey = reader.ReadNameList();
            SshNameList encClientToServer = reader.ReadNameList();
            SshNameList encServerToClient = reader.ReadNameList();
            SshNameList macClientToServer = reader.ReadNameList();
            SshNameList macServerToClient = reader.ReadNameList();
            SshNameList compClientToServer = reader.ReadNameList();
            SshNameList compServerToClient = reader.ReadNameList();
            SshNameList langClientToServer = reader.ReadNameList();
            SshNameList langServerToClient = reader.ReadNameList();
            bool firstKexPacketFollows = reader.ReadBoolean();
            reader.ReadUInt32();
            return new SshKexInit(
                cookie, kex, hostKey, encClientToServer, encServerToClient,
                macClientToServer, macServerToClient, compClientToServer, compServerToClient,
                langClientToServer, langServerToClient, firstKexPacketFollows);
        }
        catch (SshWireFormatException exception)
        {
            throw new SshKeyExchangeException("The SSH_MSG_KEXINIT message was malformed.", SshDisconnectReason.KeyExchangeFailed, exception);
        }
    }
}
