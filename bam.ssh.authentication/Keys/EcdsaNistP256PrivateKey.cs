using System.Security.Cryptography;
using Bam.Ssh.Transport;

namespace Bam.Ssh.Authentication;

/// <summary>
/// An ecdsa-sha2-nistp256 client private key (RFC 5656), signing with the BCL <see cref="ECDsa"/>.
/// The public-key blob is <c>string("ecdsa-sha2-nistp256") || string("nistp256") || string(Q)</c>
/// where Q is the uncompressed point <c>0x04 || X || Y</c>; the signature blob is
/// <c>string("ecdsa-sha2-nistp256") || string(mpint r || mpint s)</c> — exactly what
/// <c>EcdsaNistP256HostKey</c> verifies. The exchange data is hashed with SHA-256 as part of signing.
/// </summary>
public sealed class EcdsaNistP256PrivateKey : ISshPrivateKey, IDisposable
{
    private const int CoordinateLength = 32;
    private const byte UncompressedPointMarker = 0x04;

    private readonly ECDsa _ecdsa;

    /// <summary>
    /// Initializes the key from an existing <see cref="ECDsa"/> holding P-256 private parameters.
    /// Ownership transfers to this instance, which disposes it.
    /// </summary>
    /// <param name="ecdsa">The P-256 private key.</param>
    /// <exception cref="ArgumentNullException">The key is null.</exception>
    public EcdsaNistP256PrivateKey(ECDsa ecdsa)
    {
        ArgumentNullException.ThrowIfNull(ecdsa);
        _ecdsa = ecdsa;
        ECParameters parameters = ecdsa.ExportParameters(includePrivateParameters: false);
        byte[] point = new byte[1 + CoordinateLength + CoordinateLength];
        point[0] = UncompressedPointMarker;
        RightAlign(parameters.Q.X!, point.AsSpan(1, CoordinateLength));
        RightAlign(parameters.Q.Y!, point.AsSpan(1 + CoordinateLength, CoordinateLength));
        PublicKeyBlob = SshSignatureBlob.Build((ref SshWireWriter writer) =>
        {
            writer.WriteText(SshAlgorithmNames.EcdsaSha2Nistp256);
            writer.WriteText(SshAlgorithmNames.Nistp256CurveName);
            writer.WriteString(point);
        });
    }

    /// <inheritdoc/>
    public string Algorithm => SshAlgorithmNames.EcdsaSha2Nistp256;

    /// <inheritdoc/>
    public ReadOnlyMemory<byte> PublicKeyBlob { get; }

    /// <inheritdoc/>
    public byte[] Sign(ReadOnlySpan<byte> data)
    {
        byte[] ieeeSignature = _ecdsa.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        byte[] r = ieeeSignature.AsSpan(0, CoordinateLength).ToArray();
        byte[] s = ieeeSignature.AsSpan(CoordinateLength, CoordinateLength).ToArray();
        byte[] inner = SshSignatureBlob.Build((ref SshWireWriter writer) =>
        {
            writer.WriteMultiPrecisionInteger(r);
            writer.WriteMultiPrecisionInteger(s);
        });
        return SshSignatureBlob.Build((ref SshWireWriter writer) =>
        {
            writer.WriteText(SshAlgorithmNames.EcdsaSha2Nistp256);
            writer.WriteString(inner);
        });
    }

    /// <summary>
    /// Releases the underlying <see cref="ECDsa"/>.
    /// </summary>
    public void Dispose()
    {
        _ecdsa.Dispose();
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
