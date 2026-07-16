namespace Bam.Ssh.Transport;

/// <summary>
/// The locally supported algorithms, in descending preference order, that bam.ssh advertises in its
/// SSH_MSG_KEXINIT. Immutable; construct once and share. The encryption/MAC lists advertise the
/// algorithms Phase 4 will implement — they are negotiated now so the transport is ready to switch
/// ciphers as soon as those land. Compression is <c>none</c> only (D-006).
/// </summary>
public sealed class SshAlgorithmCatalog
{
    /// <summary>
    /// The default catalog: curve25519 preferred, then ECDH P-256, then DH group14; Ed25519 host
    /// keys preferred, then ECDSA P-256, then RSA SHA-2; AEAD ciphers preferred over CTR.
    /// </summary>
    public static readonly SshAlgorithmCatalog Default = new SshAlgorithmCatalog(
        keyExchange: new SshNameList(
            SshAlgorithmNames.Curve25519Sha256,
            SshAlgorithmNames.Curve25519Sha256LibsshAlias,
            SshAlgorithmNames.EcdhSha2Nistp256,
            SshAlgorithmNames.DhGroup14Sha256),
        serverHostKey: new SshNameList(
            SshAlgorithmNames.SshEd25519,
            SshAlgorithmNames.EcdsaSha2Nistp256,
            SshAlgorithmNames.RsaSha2512,
            SshAlgorithmNames.RsaSha2256),
        encryption: new SshNameList(
            SshAlgorithmNames.ChaCha20Poly1305,
            SshAlgorithmNames.Aes256Gcm,
            SshAlgorithmNames.Aes128Gcm,
            SshAlgorithmNames.Aes256Ctr),
        mac: new SshNameList(
            SshAlgorithmNames.HmacSha2256,
            SshAlgorithmNames.HmacSha2512),
        compression: new SshNameList(SshAlgorithmNames.None));

    /// <summary>
    /// Initializes a catalog from explicit preference lists.
    /// </summary>
    /// <param name="keyExchange">Key-exchange algorithms, most preferred first.</param>
    /// <param name="serverHostKey">Host-key algorithms, most preferred first.</param>
    /// <param name="encryption">Encryption algorithms (applied to both directions), most preferred first.</param>
    /// <param name="mac">MAC algorithms (applied to both directions), most preferred first.</param>
    /// <param name="compression">Compression algorithms, most preferred first.</param>
    public SshAlgorithmCatalog(
        SshNameList keyExchange,
        SshNameList serverHostKey,
        SshNameList encryption,
        SshNameList mac,
        SshNameList compression)
    {
        KeyExchange = keyExchange;
        ServerHostKey = serverHostKey;
        Encryption = encryption;
        Mac = mac;
        Compression = compression;
    }

    /// <summary>Gets the advertised key-exchange algorithms.</summary>
    public SshNameList KeyExchange { get; }

    /// <summary>Gets the advertised host-key algorithms.</summary>
    public SshNameList ServerHostKey { get; }

    /// <summary>Gets the advertised encryption algorithms (used for both directions).</summary>
    public SshNameList Encryption { get; }

    /// <summary>Gets the advertised MAC algorithms (used for both directions).</summary>
    public SshNameList Mac { get; }

    /// <summary>Gets the advertised compression algorithms.</summary>
    public SshNameList Compression { get; }
}
