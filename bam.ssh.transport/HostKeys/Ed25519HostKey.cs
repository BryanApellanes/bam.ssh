using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Bam.Ssh.Transport;

/// <summary>
/// An ssh-ed25519 host key (RFC 8709). The BCL has no Ed25519, so verification uses BouncyCastle
/// (D-009). The key blob is <c>string("ssh-ed25519") || string(32-byte public key)</c>; the signature
/// blob is <c>string("ssh-ed25519") || string(64-byte signature)</c>.
/// </summary>
public sealed class Ed25519HostKey : ISshHostKey
{
    private const int PublicKeyLength = 32;
    private const int SignatureLength = 64;

    private readonly byte[] _publicKey;

    private Ed25519HostKey(byte[] keyBlob, byte[] publicKey)
    {
        KeyBlob = keyBlob;
        _publicKey = publicKey;
        Fingerprint = SshHostKeyFingerprint.Compute(keyBlob);
    }

    /// <inheritdoc/>
    public string Algorithm => SshAlgorithmNames.SshEd25519;

    /// <inheritdoc/>
    public ReadOnlyMemory<byte> KeyBlob { get; }

    /// <inheritdoc/>
    public string Fingerprint { get; }

    /// <summary>
    /// Parses an ssh-ed25519 key blob whose leading algorithm name has already been read.
    /// </summary>
    /// <param name="keyBlob">The full K_S blob (retained verbatim).</param>
    /// <param name="reader">A reader positioned just after the algorithm name.</param>
    /// <returns>The parsed host key.</returns>
    /// <exception cref="SshKeyExchangeException">The public key field is the wrong size.</exception>
    internal static Ed25519HostKey Parse(byte[] keyBlob, ref SshWireReader reader)
    {
        ReadOnlySpan<byte> publicKey = reader.ReadString();
        if (publicKey.Length != PublicKeyLength)
        {
            throw new SshKeyExchangeException($"An ssh-ed25519 public key must be {PublicKeyLength} bytes but was {publicKey.Length}.");
        }
        return new Ed25519HostKey(keyBlob, publicKey.ToArray());
    }

    /// <inheritdoc/>
    public bool Verify(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signatureBlob)
    {
        SshWireReader reader = new SshWireReader(signatureBlob);
        string algorithm = reader.ReadText();
        if (algorithm != SshAlgorithmNames.SshEd25519)
        {
            return false;
        }
        ReadOnlySpan<byte> signature = reader.ReadString();
        if (signature.Length != SignatureLength)
        {
            return false;
        }

        Ed25519Signer signer = new Ed25519Signer();
        signer.Init(forSigning: false, new Ed25519PublicKeyParameters(_publicKey, 0));
        signer.BlockUpdate(hash.ToArray(), 0, hash.Length);
        return signer.VerifySignature(signature.ToArray());
    }
}
