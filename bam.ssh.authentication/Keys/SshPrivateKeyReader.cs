using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Bam.Ssh.Transport;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;

namespace Bam.Ssh.Authentication;

/// <summary>
/// Loads an <see cref="ISshPrivateKey"/> from PEM text, auto-detecting the container format: OpenSSH
/// v1 (<c>-----BEGIN OPENSSH PRIVATE KEY-----</c>), traditional PKCS#1 RSA / SEC1 EC, and PKCS#8
/// (plain or encrypted). RSA and ECDSA keys are imported with the BCL; Ed25519 keys — which the BCL
/// cannot represent — are imported with BouncyCastle (D-012). Encrypted PKCS#8 keys are supported via
/// the supplied passphrase; encrypted OpenSSH-v1 keys are not (see <see cref="OpenSshPrivateKeyParser"/>).
/// </summary>
public static class SshPrivateKeyReader
{
    private const string OpenSshLabel = "OPENSSH PRIVATE KEY";
    private const string RsaLabel = "RSA PRIVATE KEY";
    private const string EcLabel = "EC PRIVATE KEY";
    private const string Pkcs8Label = "PRIVATE KEY";
    private const string EncryptedPkcs8Label = "ENCRYPTED PRIVATE KEY";

    /// <summary>
    /// Reads a private key from PEM text.
    /// </summary>
    /// <param name="keyText">The PEM-encoded private key.</param>
    /// <param name="passphrase">The passphrase for an encrypted key, or null for an unencrypted key.</param>
    /// <param name="rsaSignatureAlgorithm">The rsa-sha2 variant an RSA key should sign with.</param>
    /// <returns>The parsed private key.</returns>
    /// <exception cref="ArgumentNullException">The key text is null.</exception>
    /// <exception cref="SshAuthenticationException">The format is unrecognized, unsupported, or the key could not be parsed.</exception>
    public static ISshPrivateKey Read(string keyText, string? passphrase = null, string rsaSignatureAlgorithm = SshAlgorithmNames.RsaSha2512)
    {
        ArgumentNullException.ThrowIfNull(keyText);
        string label = FindPemLabel(keyText)
            ?? throw new SshAuthenticationException("The text does not contain a recognizable PEM private key.");

        if (label == OpenSshLabel)
        {
            byte[] body = DecodePemBody(keyText, OpenSshLabel);
            return OpenSshPrivateKeyParser.Parse(body, rsaSignatureAlgorithm);
        }

        return label switch
        {
            RsaLabel => ReadRsa(keyText, passphrase, rsaSignatureAlgorithm),
            EcLabel => ReadEcdsa(keyText, passphrase),
            Pkcs8Label => ReadPkcs8(keyText, passphrase: null, rsaSignatureAlgorithm),
            EncryptedPkcs8Label => ReadPkcs8(keyText, passphrase, rsaSignatureAlgorithm),
            _ => throw new SshAuthenticationException($"Unsupported private key PEM label '-----BEGIN {label}-----'.")
        };
    }

    private static ISshPrivateKey ReadPkcs8(string keyText, string? passphrase, string rsaSignatureAlgorithm)
    {
        // A PKCS#8 container does not name its algorithm in the PEM label; try each supported family.
        if (TryReadRsa(keyText, passphrase, rsaSignatureAlgorithm, out ISshPrivateKey? rsa))
        {
            return rsa;
        }
        if (TryReadEcdsa(keyText, passphrase, out ISshPrivateKey? ecdsa))
        {
            return ecdsa;
        }
        if (TryReadEd25519(keyText, passphrase, out ISshPrivateKey? ed25519))
        {
            return ed25519;
        }
        throw new SshAuthenticationException("The PKCS#8 private key is not a supported RSA, ECDSA P-256, or Ed25519 key.");
    }

    private static ISshPrivateKey ReadRsa(string keyText, string? passphrase, string rsaSignatureAlgorithm)
    {
        if (TryReadRsa(keyText, passphrase, rsaSignatureAlgorithm, out ISshPrivateKey? key))
        {
            return key;
        }
        throw new SshAuthenticationException("The RSA private key could not be parsed.");
    }

    private static ISshPrivateKey ReadEcdsa(string keyText, string? passphrase)
    {
        if (TryReadEcdsa(keyText, passphrase, out ISshPrivateKey? key))
        {
            return key;
        }
        throw new SshAuthenticationException("The ECDSA private key could not be parsed (only nistp256 is supported).");
    }

    private static bool TryReadRsa(string keyText, string? passphrase, string rsaSignatureAlgorithm, [NotNullWhen(true)] out ISshPrivateKey? key)
    {
        RSA rsa = RSA.Create();
        try
        {
            if (passphrase is null)
            {
                rsa.ImportFromPem(keyText);
            }
            else
            {
                rsa.ImportFromEncryptedPem(keyText, passphrase);
            }
            key = new RsaPrivateKey(rsa, rsaSignatureAlgorithm);
            return true;
        }
        catch (Exception exception) when (exception is ArgumentException or CryptographicException)
        {
            rsa.Dispose();
            key = null;
            return false;
        }
    }

    private static bool TryReadEcdsa(string keyText, string? passphrase, [NotNullWhen(true)] out ISshPrivateKey? key)
    {
        ECDsa ecdsa = ECDsa.Create();
        try
        {
            if (passphrase is null)
            {
                ecdsa.ImportFromPem(keyText);
            }
            else
            {
                ecdsa.ImportFromEncryptedPem(keyText, passphrase);
            }
            // Confirm P-256; other curves are out of scope for this phase.
            ECParameters parameters = ecdsa.ExportParameters(includePrivateParameters: false);
            if (parameters.Curve.Oid.Value != ECCurve.NamedCurves.nistP256.Oid.Value &&
                parameters.Curve.Oid.FriendlyName != ECCurve.NamedCurves.nistP256.Oid.FriendlyName)
            {
                ecdsa.Dispose();
                key = null;
                return false;
            }
            key = new EcdsaNistP256PrivateKey(ecdsa);
            return true;
        }
        catch (Exception exception) when (exception is ArgumentException or CryptographicException)
        {
            ecdsa.Dispose();
            key = null;
            return false;
        }
    }

    private static bool TryReadEd25519(string keyText, string? passphrase, [NotNullWhen(true)] out ISshPrivateKey? key)
    {
        try
        {
            using System.IO.StringReader textReader = new System.IO.StringReader(keyText);
            PemReader pemReader = passphrase is null
                ? new PemReader(textReader)
                : new PemReader(textReader, new StaticPasswordFinder(passphrase));
            object pemObject = pemReader.ReadObject();
            AsymmetricKeyParameter? privateKey = pemObject switch
            {
                AsymmetricCipherKeyPair pair => pair.Private,
                AsymmetricKeyParameter parameter => parameter,
                _ => null
            };
            if (privateKey is Ed25519PrivateKeyParameters ed25519)
            {
                key = new Ed25519PrivateKey(ed25519.GetEncoded());
                return true;
            }
        }
        catch (Exception exception) when (exception is IOException or InvalidCipherTextException or ArgumentException)
        {
            // Fall through to failure.
        }
        key = null;
        return false;
    }

    private static string? FindPemLabel(string keyText)
    {
        string[] labels = new string[] { OpenSshLabel, EncryptedPkcs8Label, RsaLabel, EcLabel, Pkcs8Label };
        foreach (string label in labels)
        {
            if (keyText.Contains($"-----BEGIN {label}-----", StringComparison.Ordinal))
            {
                return label;
            }
        }
        return null;
    }

    private static byte[] DecodePemBody(string keyText, string label)
    {
        string begin = $"-----BEGIN {label}-----";
        string end = $"-----END {label}-----";
        int start = keyText.IndexOf(begin, StringComparison.Ordinal);
        int finish = keyText.IndexOf(end, StringComparison.Ordinal);
        if (start < 0 || finish < 0 || finish <= start)
        {
            throw new SshAuthenticationException($"The PEM block for '{label}' is missing its delimiters.");
        }
        string base64 = keyText.Substring(start + begin.Length, finish - (start + begin.Length))
            .Replace("\r", string.Empty)
            .Replace("\n", string.Empty)
            .Trim();
        try
        {
            return Convert.FromBase64String(base64);
        }
        catch (FormatException exception)
        {
            throw new SshAuthenticationException("The PEM body was not valid base64.", exception);
        }
    }

    private sealed class StaticPasswordFinder : IPasswordFinder
    {
        private readonly char[] _password;

        public StaticPasswordFinder(string password)
        {
            _password = password.ToCharArray();
        }

        public char[] GetPassword()
        {
            return (char[])_password.Clone();
        }
    }
}
