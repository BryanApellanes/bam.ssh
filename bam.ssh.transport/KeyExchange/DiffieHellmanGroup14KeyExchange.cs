using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;

namespace Bam.Ssh.Transport;

/// <summary>
/// The diffie-hellman-group14-sha256 key-exchange method (RFC 8268 / RFC 3526 group 14): a 2048-bit
/// MODP finite-field Diffie-Hellman with generator 2, computed with <see cref="BigInteger"/>. The
/// public value is <c>e = g^x mod p</c> as an mpint; the shared secret is <c>f^x mod p</c>. The
/// private exponent x is a random value in [2, p-2]. Single-use per exchange.
/// </summary>
public sealed class DiffieHellmanGroup14KeyExchange : ISshKeyExchangeAlgorithm
{
    // RFC 3526 §3: the 2048-bit MODP Group (id 14) prime, big-endian hex.
    private const string Group14PrimeHex =
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF";

    private static readonly BigInteger Prime = ParsePrime();
    private static readonly BigInteger Generator = new BigInteger(2);

    private readonly ISshRandom _random;
    private BigInteger _privateExponent;
    private bool _hasPrivate;

    /// <summary>
    /// Initializes the method with a randomness source for the private exponent.
    /// </summary>
    /// <param name="random">The randomness source; defaults to <see cref="SecureSshRandom.Instance"/>.</param>
    public DiffieHellmanGroup14KeyExchange(ISshRandom? random = null)
    {
        _random = random ?? SecureSshRandom.Instance;
    }

    /// <inheritdoc/>
    public string Name => SshAlgorithmNames.DhGroup14Sha256;

    /// <inheritdoc/>
    public HashAlgorithmName HashAlgorithm => HashAlgorithmName.SHA256;

    /// <inheritdoc/>
    public SshKeyExchangePublicValueFormat PublicValueFormat => SshKeyExchangePublicValueFormat.MultiPrecisionInteger;

    /// <inheritdoc/>
    public byte[] CreateClientPublicValue()
    {
        _privateExponent = GeneratePrivateExponent();
        _hasPrivate = true;
        BigInteger e = BigInteger.ModPow(Generator, _privateExponent, Prime);
        return ToUnsignedBigEndian(e);
    }

    /// <inheritdoc/>
    public byte[] DeriveSharedSecret(ReadOnlySpan<byte> peerPublicValue)
    {
        if (!_hasPrivate)
        {
            throw new InvalidOperationException("CreateClientPublicValue must be called before DeriveSharedSecret.");
        }
        BigInteger f = new BigInteger(peerPublicValue, isUnsigned: true, isBigEndian: true);

        // RFC 4253 §8: reject f outside [2, p-2].
        if (f < 2 || f > Prime - 2)
        {
            throw new SshKeyExchangeException("The diffie-hellman-group14 peer public value f is out of range [2, p-2].");
        }

        BigInteger k = BigInteger.ModPow(f, _privateExponent, Prime);
        return ToUnsignedBigEndian(k);
    }

    private BigInteger GeneratePrivateExponent()
    {
        // A 256-bit exponent gives ample security for group 14 while keeping ModPow fast.
        byte[] buffer = new byte[32];
        while (true)
        {
            _random.Fill(buffer);
            BigInteger candidate = new BigInteger(buffer, isUnsigned: true, isBigEndian: true);
            if (candidate >= 2 && candidate <= Prime - 2)
            {
                return candidate;
            }
        }
    }

    private static byte[] ToUnsignedBigEndian(BigInteger value)
    {
        return value.ToByteArray(isUnsigned: true, isBigEndian: true);
    }

    private static BigInteger ParsePrime()
    {
        // Prefix "0" so the high bit is never interpreted as a sign.
        return BigInteger.Parse("0" + Group14PrimeHex, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
    }
}
