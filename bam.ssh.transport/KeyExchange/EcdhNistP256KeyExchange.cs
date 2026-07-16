using System.Security.Cryptography;

namespace Bam.Ssh.Transport;

/// <summary>
/// The ecdh-sha2-nistp256 key-exchange method (RFC 5656) using the .NET BCL
/// <see cref="ECDiffieHellman"/> over NIST P-256. The public value is the uncompressed SEC1 point
/// encoding (<c>0x04 || X || Y</c>, 65 bytes) transmitted as an SSH string; the shared secret is the
/// X coordinate of the agreed point, encoded as an mpint. Single-use per exchange.
/// </summary>
public sealed class EcdhNistP256KeyExchange : ISshKeyExchangeAlgorithm
{
    private const int CoordinateLength = 32;
    private const byte UncompressedPointMarker = 0x04;

    private ECDiffieHellman? _ecdh;

    /// <inheritdoc/>
    public string Name => SshAlgorithmNames.EcdhSha2Nistp256;

    /// <inheritdoc/>
    public HashAlgorithmName HashAlgorithm => HashAlgorithmName.SHA256;

    /// <inheritdoc/>
    public SshKeyExchangePublicValueFormat PublicValueFormat => SshKeyExchangePublicValueFormat.String;

    /// <inheritdoc/>
    public byte[] CreateClientPublicValue()
    {
        _ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        ECParameters parameters = _ecdh.ExportParameters(includePrivateParameters: false);
        byte[] x = parameters.Q.X!;
        byte[] y = parameters.Q.Y!;

        byte[] encoded = new byte[1 + CoordinateLength + CoordinateLength];
        encoded[0] = UncompressedPointMarker;
        CopyRightAligned(x, encoded.AsSpan(1, CoordinateLength));
        CopyRightAligned(y, encoded.AsSpan(1 + CoordinateLength, CoordinateLength));
        return encoded;
    }

    /// <inheritdoc/>
    public byte[] DeriveSharedSecret(ReadOnlySpan<byte> peerPublicValue)
    {
        if (_ecdh is null)
        {
            throw new InvalidOperationException("CreateClientPublicValue must be called before DeriveSharedSecret.");
        }
        if (peerPublicValue.Length != 1 + CoordinateLength + CoordinateLength || peerPublicValue[0] != UncompressedPointMarker)
        {
            throw new SshKeyExchangeException("The ecdh-sha2-nistp256 peer public value is not a valid uncompressed P-256 point.");
        }

        ECParameters peerParameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = peerPublicValue.Slice(1, CoordinateLength).ToArray(),
                Y = peerPublicValue.Slice(1 + CoordinateLength, CoordinateLength).ToArray()
            }
        };

        try
        {
            using ECDiffieHellman peer = ECDiffieHellman.Create(peerParameters);
            return _ecdh.DeriveRawSecretAgreement(peer.PublicKey);
        }
        catch (CryptographicException exception)
        {
            throw new SshKeyExchangeException("The ecdh-sha2-nistp256 peer public value is not a valid point on the curve.", SshDisconnectReason.KeyExchangeFailed, exception);
        }
    }

    private static void CopyRightAligned(byte[] source, Span<byte> destination)
    {
        // BCL exports coordinates as fixed 32-byte big-endian, but guard against a shorter/longer array.
        if (source.Length == destination.Length)
        {
            source.CopyTo(destination);
            return;
        }
        destination.Clear();
        if (source.Length < destination.Length)
        {
            source.CopyTo(destination.Slice(destination.Length - source.Length));
        }
        else
        {
            source.AsSpan(source.Length - destination.Length).CopyTo(destination);
        }
    }
}
