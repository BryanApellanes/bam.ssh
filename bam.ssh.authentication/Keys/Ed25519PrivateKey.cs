using Bam.Ssh.Transport;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Bam.Ssh.Authentication;

/// <summary>
/// An ssh-ed25519 client private key (RFC 8709). The BCL has no Ed25519, so signing uses BouncyCastle
/// (D-012). The public-key blob is <c>string("ssh-ed25519") || string(32-byte public key)</c> and the
/// signature blob is <c>string("ssh-ed25519") || string(64-byte signature)</c> — exactly what
/// <c>Ed25519HostKey</c> verifies.
/// </summary>
public sealed class Ed25519PrivateKey : ISshPrivateKey
{
    private const int SeedLength = 32;

    private readonly Ed25519PrivateKeyParameters _privateKey;

    /// <summary>
    /// Initializes the key from a 32-byte Ed25519 seed (the private scalar seed OpenSSH stores).
    /// </summary>
    /// <param name="seed">The 32-byte Ed25519 seed.</param>
    /// <exception cref="ArgumentNullException">The seed is null.</exception>
    /// <exception cref="SshAuthenticationException">The seed is not 32 bytes.</exception>
    public Ed25519PrivateKey(byte[] seed)
    {
        ArgumentNullException.ThrowIfNull(seed);
        if (seed.Length != SeedLength)
        {
            throw new SshAuthenticationException($"An Ed25519 seed must be {SeedLength} bytes but was {seed.Length}.");
        }
        _privateKey = new Ed25519PrivateKeyParameters(seed, 0);
        byte[] publicKey = _privateKey.GeneratePublicKey().GetEncoded();
        PublicKeyBlob = SshSignatureBlob.Build((ref SshWireWriter writer) =>
        {
            writer.WriteText(SshAlgorithmNames.SshEd25519);
            writer.WriteString(publicKey);
        });
    }

    /// <inheritdoc/>
    public string Algorithm => SshAlgorithmNames.SshEd25519;

    /// <inheritdoc/>
    public ReadOnlyMemory<byte> PublicKeyBlob { get; }

    /// <inheritdoc/>
    public byte[] Sign(ReadOnlySpan<byte> data)
    {
        Ed25519Signer signer = new Ed25519Signer();
        signer.Init(forSigning: true, _privateKey);
        byte[] buffer = data.ToArray();
        signer.BlockUpdate(buffer, 0, buffer.Length);
        byte[] signature = signer.GenerateSignature();
        return SshSignatureBlob.Build((ref SshWireWriter writer) =>
        {
            writer.WriteText(SshAlgorithmNames.SshEd25519);
            writer.WriteString(signature);
        });
    }
}
