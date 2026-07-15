namespace Bam.Ssh;

/// <summary>
/// Supplies cryptographically secure random bytes to the protocol stack (packet padding,
/// cookies, nonces). Injected rather than accessed statically so tests can substitute a
/// deterministic source and so the security requirement — all randomness comes from
/// <see cref="System.Security.Cryptography.RandomNumberGenerator"/> — is satisfied in exactly one place
/// (<see cref="SecureSshRandom"/>).
/// </summary>
public interface ISshRandom
{
    /// <summary>
    /// Fills the destination span with random bytes. Implementations must fill every byte
    /// and must be safe for concurrent use from multiple threads.
    /// </summary>
    /// <param name="destination">The span to fill.</param>
    void Fill(Span<byte> destination);
}
