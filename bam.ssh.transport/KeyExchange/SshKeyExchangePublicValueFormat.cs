namespace Bam.Ssh.Transport;

/// <summary>
/// How a key-exchange method encodes its public values (the client's and server's contributions)
/// when they are fed into the exchange hash. Elliptic-curve methods transmit opaque byte strings;
/// finite-field Diffie-Hellman transmits multiple-precision integers.
/// </summary>
public enum SshKeyExchangePublicValueFormat
{
    /// <summary>Public values are SSH strings (ECDH: raw curve points / X25519 keys).</summary>
    String = 0,

    /// <summary>Public values are SSH mpints (finite-field DH: e and f).</summary>
    MultiPrecisionInteger = 1
}
