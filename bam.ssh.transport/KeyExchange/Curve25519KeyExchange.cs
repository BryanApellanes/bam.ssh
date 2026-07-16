using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Bam.Ssh.Transport;

/// <summary>
/// The curve25519-sha256 key-exchange method (RFC 8731) using X25519. The .NET BCL has no X25519, so
/// this is one of the two places BouncyCastle is used (D-009). The public value is the 32-byte
/// X25519 public key (an SSH string); the shared secret is the 32-byte agreement output interpreted
/// as an unsigned big-endian integer and encoded as an mpint. Single-use per exchange.
/// </summary>
public sealed class Curve25519KeyExchange : ISshKeyExchangeAlgorithm
{
    /// <summary>The X25519 public/private key size and agreement output size in bytes.</summary>
    public const int KeySize = 32;

    private readonly ISshRandom _random;
    private X25519PrivateKeyParameters? _privateKey;

    /// <summary>
    /// Initializes the method with a randomness source for the ephemeral key.
    /// </summary>
    /// <param name="random">The randomness source; defaults to <see cref="SecureSshRandom.Instance"/>.</param>
    public Curve25519KeyExchange(ISshRandom? random = null)
    {
        _random = random ?? SecureSshRandom.Instance;
    }

    /// <inheritdoc/>
    public string Name => SshAlgorithmNames.Curve25519Sha256;

    /// <inheritdoc/>
    public HashAlgorithmName HashAlgorithm => HashAlgorithmName.SHA256;

    /// <inheritdoc/>
    public SshKeyExchangePublicValueFormat PublicValueFormat => SshKeyExchangePublicValueFormat.String;

    /// <inheritdoc/>
    public byte[] CreateClientPublicValue()
    {
        byte[] seed = new byte[KeySize];
        _random.Fill(seed);
        _privateKey = new X25519PrivateKeyParameters(seed, 0);
        CryptographicOperations.ZeroMemory(seed);
        X25519PublicKeyParameters publicKey = _privateKey.GeneratePublicKey();
        return publicKey.GetEncoded();
    }

    /// <inheritdoc/>
    public byte[] DeriveSharedSecret(ReadOnlySpan<byte> peerPublicValue)
    {
        if (_privateKey is null)
        {
            throw new InvalidOperationException("CreateClientPublicValue must be called before DeriveSharedSecret.");
        }
        if (peerPublicValue.Length != KeySize)
        {
            throw new SshKeyExchangeException($"The curve25519 peer public value must be {KeySize} bytes but was {peerPublicValue.Length}.");
        }

        X25519PublicKeyParameters peerKey = new X25519PublicKeyParameters(peerPublicValue.ToArray(), 0);
        X25519Agreement agreement = new X25519Agreement();
        agreement.Init(_privateKey);
        byte[] secret = new byte[agreement.AgreementSize];
        agreement.CalculateAgreement(peerKey, secret, 0);

        // RFC 8731: an all-zero agreement means the peer sent a low-order point; reject it.
        if (IsAllZero(secret))
        {
            CryptographicOperations.ZeroMemory(secret);
            throw new SshKeyExchangeException("The curve25519 key agreement produced an all-zero shared secret (invalid peer point).");
        }
        return secret;
    }

    private static bool IsAllZero(ReadOnlySpan<byte> value)
    {
        return value.IndexOfAnyExcept((byte)0) < 0;
    }
}
