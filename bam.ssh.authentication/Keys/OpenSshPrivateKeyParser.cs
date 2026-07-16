using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Bam.Ssh.Transport;

namespace Bam.Ssh.Authentication;

/// <summary>
/// Parses an unencrypted OpenSSH private key (the <c>-----BEGIN OPENSSH PRIVATE KEY-----</c> /
/// <c>openssh-key-v1</c> format) into an <see cref="ISshPrivateKey"/> for ssh-ed25519,
/// ecdsa-sha2-nistp256, or ssh-rsa keys. The binary body is decoded with the reused
/// <see cref="SshWireReader"/>. Encrypted keys (cipher other than <c>none</c>, protected by
/// bcrypt-pbkdf) are out of scope for this phase and raise <see cref="SshAuthenticationException"/>
/// (D-012).
/// </summary>
public static class OpenSshPrivateKeyParser
{
    private const string Magic = "openssh-key-v1";
    private const string NoneCipher = "none";
    private const int Ed25519SeedLength = 32;
    private const int EcdsaCoordinateLength = 32;

    /// <summary>
    /// Parses the decoded openssh-key-v1 body.
    /// </summary>
    /// <param name="body">The base64-decoded key body (everything between the PEM header and footer).</param>
    /// <param name="rsaSignatureAlgorithm">The rsa-sha2 variant an RSA key should sign with.</param>
    /// <returns>The parsed private key.</returns>
    /// <exception cref="SshAuthenticationException">The body is malformed, encrypted, or an unsupported key type.</exception>
    public static ISshPrivateKey Parse(ReadOnlySpan<byte> body, string rsaSignatureAlgorithm = SshAlgorithmNames.RsaSha2512)
    {
        try
        {
            SshWireReader reader = new SshWireReader(body);
            ReadOnlySpan<byte> magic = reader.ReadRaw(Magic.Length + 1);
            if (!magic.Slice(0, Magic.Length).SequenceEqual(Encoding.ASCII.GetBytes(Magic)) || magic[Magic.Length] != 0)
            {
                throw new SshAuthenticationException("The OpenSSH private key is missing the openssh-key-v1 magic header.");
            }

            string cipherName = reader.ReadText();
            string kdfName = reader.ReadText();
            reader.ReadString(); // kdf options
            if (cipherName != NoneCipher || kdfName != NoneCipher)
            {
                throw new SshAuthenticationException(
                    $"Encrypted OpenSSH private keys (cipher '{cipherName}', kdf '{kdfName}') are not supported in this phase; decrypt the key or use an unencrypted or PKCS#8 key.");
            }

            uint keyCount = reader.ReadUInt32();
            if (keyCount != 1)
            {
                throw new SshAuthenticationException($"Expected exactly one key in the OpenSSH file but found {keyCount}.");
            }

            reader.ReadString(); // public key blob (recomputed from the private section below)
            ReadOnlySpan<byte> privateSection = reader.ReadString();

            SshWireReader privateReader = new SshWireReader(privateSection);
            uint checkInt1 = privateReader.ReadUInt32();
            uint checkInt2 = privateReader.ReadUInt32();
            if (checkInt1 != checkInt2)
            {
                throw new SshAuthenticationException("The OpenSSH private key check integers do not match (corrupt or wrongly decrypted).");
            }

            string keyType = privateReader.ReadText();
            return keyType switch
            {
                SshAlgorithmNames.SshEd25519 => ParseEd25519(ref privateReader),
                SshAlgorithmNames.EcdsaSha2Nistp256 => ParseEcdsa(ref privateReader),
                SshAlgorithmNames.SshRsaKeyType => ParseRsa(ref privateReader, rsaSignatureAlgorithm),
                _ => throw new SshAuthenticationException($"Unsupported OpenSSH private key type '{keyType}'.")
            };
        }
        catch (SshWireFormatException exception)
        {
            throw new SshAuthenticationException("The OpenSSH private key body was malformed.", exception);
        }
    }

    private static ISshPrivateKey ParseEd25519(ref SshWireReader reader)
    {
        reader.ReadString(); // public key (32 bytes) — derivable from the seed
        ReadOnlySpan<byte> privateKey = reader.ReadString();
        if (privateKey.Length != 64)
        {
            throw new SshAuthenticationException($"An OpenSSH ed25519 private field must be 64 bytes but was {privateKey.Length}.");
        }
        return new Ed25519PrivateKey(privateKey.Slice(0, Ed25519SeedLength).ToArray());
    }

    private static ISshPrivateKey ParseEcdsa(ref SshWireReader reader)
    {
        string curve = reader.ReadText();
        if (curve != SshAlgorithmNames.Nistp256CurveName)
        {
            throw new SshAuthenticationException($"Unsupported ECDSA curve '{curve}'; only nistp256 is supported.");
        }
        ReadOnlySpan<byte> point = reader.ReadString();
        if (point.Length != 1 + EcdsaCoordinateLength + EcdsaCoordinateLength || point[0] != 0x04)
        {
            throw new SshAuthenticationException("The OpenSSH ecdsa public point is not a valid uncompressed P-256 point.");
        }
        byte[] d = LeftPad(reader.ReadMultiPrecisionIntegerMagnitude(), EcdsaCoordinateLength);

        ECParameters parameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = point.Slice(1, EcdsaCoordinateLength).ToArray(),
                Y = point.Slice(1 + EcdsaCoordinateLength, EcdsaCoordinateLength).ToArray()
            },
            D = d
        };
        return new EcdsaNistP256PrivateKey(ECDsa.Create(parameters));
    }

    private static ISshPrivateKey ParseRsa(ref SshWireReader reader, string rsaSignatureAlgorithm)
    {
        byte[] modulus = reader.ReadMultiPrecisionIntegerMagnitude().ToArray();
        byte[] exponent = reader.ReadMultiPrecisionIntegerMagnitude().ToArray();
        byte[] d = reader.ReadMultiPrecisionIntegerMagnitude().ToArray();
        byte[] inverseQ = reader.ReadMultiPrecisionIntegerMagnitude().ToArray();
        byte[] p = reader.ReadMultiPrecisionIntegerMagnitude().ToArray();
        byte[] q = reader.ReadMultiPrecisionIntegerMagnitude().ToArray();

        int modulusLength = modulus.Length;
        int halfLength = (modulusLength + 1) / 2;

        BigInteger bigD = ToBigInteger(d);
        BigInteger bigP = ToBigInteger(p);
        BigInteger bigQ = ToBigInteger(q);
        byte[] dp = ToFixed(bigD % (bigP - BigInteger.One), halfLength);
        byte[] dq = ToFixed(bigD % (bigQ - BigInteger.One), halfLength);

        RSAParameters parameters = new RSAParameters
        {
            Modulus = modulus,
            Exponent = exponent,
            D = LeftPad(d, modulusLength),
            P = LeftPad(p, halfLength),
            Q = LeftPad(q, halfLength),
            DP = dp,
            DQ = dq,
            InverseQ = LeftPad(inverseQ, halfLength)
        };
        RSA rsa = RSA.Create();
        try
        {
            rsa.ImportParameters(parameters);
        }
        catch (CryptographicException exception)
        {
            rsa.Dispose();
            throw new SshAuthenticationException("The OpenSSH RSA private key parameters were invalid.", exception);
        }
        return new RsaPrivateKey(rsa, rsaSignatureAlgorithm);
    }

    private static BigInteger ToBigInteger(ReadOnlySpan<byte> unsignedBigEndian)
    {
        return new BigInteger(unsignedBigEndian, isUnsigned: true, isBigEndian: true);
    }

    private static byte[] ToFixed(BigInteger value, int length)
    {
        return LeftPad(value.ToByteArray(isUnsigned: true, isBigEndian: true), length);
    }

    private static byte[] LeftPad(ReadOnlySpan<byte> value, int length)
    {
        if (value.Length == length)
        {
            return value.ToArray();
        }
        if (value.Length > length)
        {
            // Strip leading zeros to reach the target length; a genuine overflow is a malformed key.
            ReadOnlySpan<byte> trimmed = value;
            while (trimmed.Length > length && trimmed[0] == 0)
            {
                trimmed = trimmed.Slice(1);
            }
            if (trimmed.Length != length)
            {
                throw new SshAuthenticationException($"A key component was {value.Length} bytes; cannot fit {length}.");
            }
            return trimmed.ToArray();
        }
        byte[] padded = new byte[length];
        value.CopyTo(padded.AsSpan(length - value.Length));
        return padded;
    }
}
