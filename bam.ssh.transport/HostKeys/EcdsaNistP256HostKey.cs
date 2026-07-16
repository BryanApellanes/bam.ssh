using System.Security.Cryptography;

namespace Bam.Ssh.Transport;

/// <summary>
/// An ecdsa-sha2-nistp256 host key (RFC 5656), verified with the BCL <see cref="ECDsa"/>. The key
/// blob is <c>string("ecdsa-sha2-nistp256") || string("nistp256") || string(Q)</c> where Q is the
/// uncompressed point <c>0x04 || X || Y</c>. The signature blob is
/// <c>string("ecdsa-sha2-nistp256") || string(mpint r || mpint s)</c>; ECDSA hashes the exchange
/// hash H with SHA-256 as part of verification.
/// </summary>
public sealed class EcdsaNistP256HostKey : ISshHostKey
{
    private const int CoordinateLength = 32;
    private const byte UncompressedPointMarker = 0x04;

    private readonly byte[] _x;
    private readonly byte[] _y;

    private EcdsaNistP256HostKey(byte[] keyBlob, byte[] x, byte[] y)
    {
        KeyBlob = keyBlob;
        _x = x;
        _y = y;
        Fingerprint = SshHostKeyFingerprint.Compute(keyBlob);
    }

    /// <inheritdoc/>
    public string Algorithm => SshAlgorithmNames.EcdsaSha2Nistp256;

    /// <inheritdoc/>
    public ReadOnlyMemory<byte> KeyBlob { get; }

    /// <inheritdoc/>
    public string Fingerprint { get; }

    /// <summary>
    /// Parses an ecdsa-sha2-nistp256 key blob whose leading algorithm name has already been read.
    /// </summary>
    /// <param name="keyBlob">The full K_S blob (retained verbatim).</param>
    /// <param name="reader">A reader positioned just after the algorithm name.</param>
    /// <returns>The parsed host key.</returns>
    /// <exception cref="SshKeyExchangeException">The curve identifier or point encoding is invalid.</exception>
    internal static EcdsaNistP256HostKey Parse(byte[] keyBlob, ref SshWireReader reader)
    {
        string curve = reader.ReadText();
        if (curve != SshAlgorithmNames.Nistp256CurveName)
        {
            throw new SshKeyExchangeException($"Expected ECDSA curve '{SshAlgorithmNames.Nistp256CurveName}' but got '{curve}'.");
        }
        ReadOnlySpan<byte> point = reader.ReadString();
        if (point.Length != 1 + CoordinateLength + CoordinateLength || point[0] != UncompressedPointMarker)
        {
            throw new SshKeyExchangeException("The ecdsa-sha2-nistp256 public point is not a valid uncompressed P-256 point.");
        }
        byte[] x = point.Slice(1, CoordinateLength).ToArray();
        byte[] y = point.Slice(1 + CoordinateLength, CoordinateLength).ToArray();
        return new EcdsaNistP256HostKey(keyBlob, x, y);
    }

    /// <inheritdoc/>
    public bool Verify(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signatureBlob)
    {
        SshWireReader reader = new SshWireReader(signatureBlob);
        string algorithm = reader.ReadText();
        if (algorithm != SshAlgorithmNames.EcdsaSha2Nistp256)
        {
            return false;
        }

        ReadOnlySpan<byte> inner = reader.ReadString();
        SshWireReader innerReader = new SshWireReader(inner);
        ReadOnlySpan<byte> r;
        ReadOnlySpan<byte> s;
        try
        {
            r = innerReader.ReadMultiPrecisionIntegerMagnitude();
            s = innerReader.ReadMultiPrecisionIntegerMagnitude();
        }
        catch (SshWireFormatException)
        {
            return false;
        }

        byte[] ieeeSignature = new byte[CoordinateLength * 2];
        RightAlign(r, ieeeSignature.AsSpan(0, CoordinateLength));
        RightAlign(s, ieeeSignature.AsSpan(CoordinateLength, CoordinateLength));

        ECParameters parameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = _x, Y = _y }
        };
        try
        {
            using ECDsa ecdsa = ECDsa.Create(parameters);
            return ecdsa.VerifyData(hash, ieeeSignature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static void RightAlign(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        destination.Clear();
        if (source.Length <= destination.Length)
        {
            source.CopyTo(destination.Slice(destination.Length - source.Length));
        }
        else
        {
            source.Slice(source.Length - destination.Length).CopyTo(destination);
        }
    }
}
