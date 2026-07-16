namespace Bam.Ssh.Transport;

/// <summary>
/// The canonical algorithm name strings bam.ssh understands, as they appear on the wire in
/// SSH_MSG_KEXINIT name-lists (RFC 4253, RFC 5656, RFC 8731, RFC 8332, RFC 8709). Centralized so
/// negotiation, the algorithm factories, and tests refer to one spelling.
/// </summary>
public static class SshAlgorithmNames
{
    /// <summary>curve25519-sha256 key exchange (RFC 8731); also accepted under its legacy alias.</summary>
    public const string Curve25519Sha256 = "curve25519-sha256";

    /// <summary>The pre-standard alias for curve25519-sha256 used by OpenSSH.</summary>
    public const string Curve25519Sha256LibsshAlias = "curve25519-sha256@libssh.org";

    /// <summary>ecdh-sha2-nistp256 key exchange (RFC 5656).</summary>
    public const string EcdhSha2Nistp256 = "ecdh-sha2-nistp256";

    /// <summary>diffie-hellman-group14-sha256 key exchange (RFC 8268 / RFC 3526 group 14).</summary>
    public const string DhGroup14Sha256 = "diffie-hellman-group14-sha256";

    /// <summary>Ed25519 host key / signature algorithm (RFC 8709).</summary>
    public const string SshEd25519 = "ssh-ed25519";

    /// <summary>ECDSA over NIST P-256 host key / signature algorithm (RFC 5656).</summary>
    public const string EcdsaSha2Nistp256 = "ecdsa-sha2-nistp256";

    /// <summary>RSA host key with SHA-256 signatures (RFC 8332). Key blob is transmitted as ssh-rsa.</summary>
    public const string RsaSha2256 = "rsa-sha2-256";

    /// <summary>RSA host key with SHA-512 signatures (RFC 8332). Key blob is transmitted as ssh-rsa.</summary>
    public const string RsaSha2512 = "rsa-sha2-512";

    /// <summary>The ssh-rsa key blob type name (used inside K_S for both rsa-sha2-256 and rsa-sha2-512).</summary>
    public const string SshRsaKeyType = "ssh-rsa";

    /// <summary>The nistp256 curve identifier used inside ECDSA and ECDH blobs.</summary>
    public const string Nistp256CurveName = "nistp256";

    /// <summary>chacha20-poly1305@openssh.com authenticated cipher (implemented in Phase 4).</summary>
    public const string ChaCha20Poly1305 = "chacha20-poly1305@openssh.com";

    /// <summary>aes256-gcm@openssh.com authenticated cipher (implemented in Phase 4).</summary>
    public const string Aes256Gcm = "aes256-gcm@openssh.com";

    /// <summary>aes128-gcm@openssh.com authenticated cipher (implemented in Phase 4).</summary>
    public const string Aes128Gcm = "aes128-gcm@openssh.com";

    /// <summary>aes256-ctr cipher (RFC 4344).</summary>
    public const string Aes256Ctr = "aes256-ctr";

    /// <summary>aes128-ctr cipher (RFC 4344).</summary>
    public const string Aes128Ctr = "aes128-ctr";

    /// <summary>hmac-sha2-256 message authentication (implemented in Phase 4).</summary>
    public const string HmacSha2256 = "hmac-sha2-256";

    /// <summary>hmac-sha2-512 message authentication (implemented in Phase 4).</summary>
    public const string HmacSha2512 = "hmac-sha2-512";

    /// <summary>The "none" algorithm name (no compression; the only compression bam.ssh offers initially).</summary>
    public const string None = "none";
}
