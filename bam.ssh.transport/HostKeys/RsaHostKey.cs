using System.Security.Cryptography;

namespace Bam.Ssh.Transport;

/// <summary>
/// An ssh-rsa host key verified with rsa-sha2-256 or rsa-sha2-512 signatures (RFC 8332), using the
/// BCL <see cref="RSA"/>. The key blob is <c>string("ssh-rsa") || mpint(e) || mpint(n)</c> — note the
/// blob type is always <c>ssh-rsa</c> even when the signature uses SHA-2. The signature blob is
/// <c>string("rsa-sha2-256"|"rsa-sha2-512") || string(signature)</c>; the signature name selects the
/// digest. Legacy SHA-1 <c>ssh-rsa</c> signatures are rejected (no SHA-1, per project policy).
/// </summary>
public sealed class RsaHostKey : ISshHostKey
{
    private readonly byte[] _modulus;
    private readonly byte[] _exponent;

    private RsaHostKey(byte[] keyBlob, byte[] modulus, byte[] exponent)
    {
        KeyBlob = keyBlob;
        _modulus = modulus;
        _exponent = exponent;
        Fingerprint = SshHostKeyFingerprint.Compute(keyBlob);
    }

    /// <inheritdoc/>
    public string Algorithm => SshAlgorithmNames.SshRsaKeyType;

    /// <inheritdoc/>
    public ReadOnlyMemory<byte> KeyBlob { get; }

    /// <inheritdoc/>
    public string Fingerprint { get; }

    /// <summary>
    /// Parses an ssh-rsa key blob whose leading algorithm name has already been read.
    /// </summary>
    /// <param name="keyBlob">The full K_S blob (retained verbatim).</param>
    /// <param name="reader">A reader positioned just after the algorithm name.</param>
    /// <returns>The parsed host key.</returns>
    /// <exception cref="SshKeyExchangeException">The e or n field is malformed.</exception>
    internal static RsaHostKey Parse(byte[] keyBlob, ref SshWireReader reader)
    {
        try
        {
            byte[] exponent = reader.ReadMultiPrecisionIntegerMagnitude().ToArray();
            byte[] modulus = reader.ReadMultiPrecisionIntegerMagnitude().ToArray();
            return new RsaHostKey(keyBlob, modulus, exponent);
        }
        catch (SshWireFormatException exception)
        {
            throw new SshKeyExchangeException("The ssh-rsa host key blob was malformed.", SshDisconnectReason.KeyExchangeFailed, exception);
        }
    }

    /// <inheritdoc/>
    public bool Verify(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signatureBlob)
    {
        SshWireReader reader = new SshWireReader(signatureBlob);
        string algorithm = reader.ReadText();
        HashAlgorithmName hashAlgorithm;
        if (algorithm == SshAlgorithmNames.RsaSha2256)
        {
            hashAlgorithm = HashAlgorithmName.SHA256;
        }
        else if (algorithm == SshAlgorithmNames.RsaSha2512)
        {
            hashAlgorithm = HashAlgorithmName.SHA512;
        }
        else
        {
            // Reject ssh-rsa (SHA-1) and anything else.
            return false;
        }

        ReadOnlySpan<byte> signature = reader.ReadString();
        RSAParameters parameters = new RSAParameters
        {
            Modulus = _modulus,
            Exponent = _exponent
        };
        try
        {
            using RSA rsa = RSA.Create();
            rsa.ImportParameters(parameters);
            return rsa.VerifyData(hash, signature, hashAlgorithm, RSASignaturePadding.Pkcs1);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }
}
