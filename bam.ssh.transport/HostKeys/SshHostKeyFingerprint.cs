using System.Security.Cryptography;

namespace Bam.Ssh.Transport;

/// <summary>
/// Computes the OpenSSH-style host-key fingerprint: <c>SHA256:</c> followed by the unpadded Base64 of
/// the SHA-256 digest of the key blob. Shared by the host-key implementations.
/// </summary>
internal static class SshHostKeyFingerprint
{
    /// <summary>
    /// Computes the <c>SHA256:base64</c> fingerprint for a host-key blob.
    /// </summary>
    /// <param name="keyBlob">The K_S host-key blob.</param>
    /// <returns>The fingerprint string.</returns>
    public static string Compute(ReadOnlySpan<byte> keyBlob)
    {
        byte[] digest = SHA256.HashData(keyBlob);
        string base64 = Convert.ToBase64String(digest).TrimEnd('=');
        return $"SHA256:{base64}";
    }
}
