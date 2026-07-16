using System.Security.Cryptography;
using Bam.Ssh.Transport;

namespace Bam.Ssh.Authentication;

/// <summary>
/// An RSA client private key signing with rsa-sha2-256 or rsa-sha2-512 (RFC 8332), using the BCL
/// <see cref="RSA"/>. The public-key blob is <c>string("ssh-rsa") || mpint(e) || mpint(n)</c> — note
/// the blob type is always <c>ssh-rsa</c> even when the signature uses SHA-2 — and the signature blob
/// is <c>string("rsa-sha2-256"|"rsa-sha2-512") || string(signature)</c>, exactly what
/// <c>RsaHostKey</c> verifies. SHA-1 <c>ssh-rsa</c> signatures are never produced (no SHA-1, per
/// project policy).
/// </summary>
public sealed class RsaPrivateKey : ISshPrivateKey, IDisposable
{
    private readonly RSA _rsa;
    private readonly HashAlgorithmName _hashAlgorithm;

    /// <summary>
    /// Initializes the key from an existing <see cref="RSA"/> holding private parameters, selecting the
    /// SHA-2 signature variant. Ownership transfers to this instance, which disposes it.
    /// </summary>
    /// <param name="rsa">The RSA private key.</param>
    /// <param name="signatureAlgorithm">
    /// The signature algorithm name: <c>rsa-sha2-256</c> (default) or <c>rsa-sha2-512</c>.
    /// </param>
    /// <exception cref="ArgumentNullException">The key is null.</exception>
    /// <exception cref="SshAuthenticationException">The signature algorithm name is not a supported rsa-sha2 variant.</exception>
    public RsaPrivateKey(RSA rsa, string signatureAlgorithm = SshAlgorithmNames.RsaSha2256)
    {
        ArgumentNullException.ThrowIfNull(rsa);
        ArgumentNullException.ThrowIfNull(signatureAlgorithm);
        if (signatureAlgorithm == SshAlgorithmNames.RsaSha2256)
        {
            _hashAlgorithm = HashAlgorithmName.SHA256;
        }
        else if (signatureAlgorithm == SshAlgorithmNames.RsaSha2512)
        {
            _hashAlgorithm = HashAlgorithmName.SHA512;
        }
        else
        {
            throw new SshAuthenticationException($"Unsupported RSA signature algorithm '{signatureAlgorithm}'; expected rsa-sha2-256 or rsa-sha2-512.");
        }

        _rsa = rsa;
        Algorithm = signatureAlgorithm;
        RSAParameters parameters = rsa.ExportParameters(includePrivateParameters: false);
        byte[] exponent = parameters.Exponent!;
        byte[] modulus = parameters.Modulus!;
        PublicKeyBlob = SshSignatureBlob.Build((ref SshWireWriter writer) =>
        {
            writer.WriteText(SshAlgorithmNames.SshRsaKeyType);
            writer.WriteMultiPrecisionInteger(exponent);
            writer.WriteMultiPrecisionInteger(modulus);
        });
    }

    /// <inheritdoc/>
    public string Algorithm { get; }

    /// <inheritdoc/>
    public ReadOnlyMemory<byte> PublicKeyBlob { get; }

    /// <inheritdoc/>
    public byte[] Sign(ReadOnlySpan<byte> data)
    {
        byte[] signature = _rsa.SignData(data, _hashAlgorithm, RSASignaturePadding.Pkcs1);
        string algorithm = Algorithm;
        return SshSignatureBlob.Build((ref SshWireWriter writer) =>
        {
            writer.WriteText(algorithm);
            writer.WriteString(signature);
        });
    }

    /// <summary>
    /// Releases the underlying <see cref="RSA"/>.
    /// </summary>
    public void Dispose()
    {
        _rsa.Dispose();
    }
}
