using System.Security.Cryptography;

namespace Bam.Ssh;

/// <summary>
/// The production <see cref="ISshRandom"/> backed by
/// <see cref="RandomNumberGenerator.Fill(Span{byte})"/>. Stateless and thread-safe;
/// use <see cref="Instance"/> rather than constructing new instances.
/// </summary>
public sealed class SecureSshRandom : ISshRandom
{
    /// <summary>
    /// Gets the shared instance. The type is stateless, so one instance serves the whole process.
    /// </summary>
    public static SecureSshRandom Instance { get; } = new SecureSshRandom();

    /// <summary>
    /// Fills the destination span with cryptographically secure random bytes.
    /// </summary>
    /// <param name="destination">The span to fill.</param>
    public void Fill(Span<byte> destination)
    {
        RandomNumberGenerator.Fill(destination);
    }
}
