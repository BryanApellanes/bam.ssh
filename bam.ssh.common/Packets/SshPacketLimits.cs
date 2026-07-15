namespace Bam.Ssh;

/// <summary>
/// Immutable decode-side protection limits for packet framing. The decoder validates every
/// incoming packet_length against these bounds before committing any buffering or slicing,
/// which is the primary defense against oversized-packet and resource-exhaustion attacks.
/// </summary>
public sealed class SshPacketLimits
{
    /// <summary>
    /// The smallest legal value of the packet_length field: one padding_length byte plus the
    /// four mandatory padding bytes (an empty payload).
    /// </summary>
    public const uint MinimumPacketLength = 5;

    /// <summary>
    /// The RFC 4253 §6.1 floor for what an implementation must be able to accept:
    /// a total packet size of 35000 bytes.
    /// </summary>
    public const int RequiredAcceptedPacketLength = 35000;

    /// <summary>
    /// The default limits: a 262144-byte (256 KiB) maximum packet length, matching OpenSSH,
    /// giving interop headroom for SFTP payloads while still bounding resource use.
    /// </summary>
    public static readonly SshPacketLimits Default = new SshPacketLimits(262144);

    /// <summary>
    /// Initializes limits with the given maximum accepted packet_length.
    /// </summary>
    /// <param name="maxPacketLength">The largest packet_length field value the decoder accepts. Must be at least <see cref="RequiredAcceptedPacketLength"/> to remain RFC-conformant.</param>
    /// <exception cref="ArgumentOutOfRangeException">The maximum is below the RFC 4253 must-accept floor.</exception>
    public SshPacketLimits(int maxPacketLength)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maxPacketLength, RequiredAcceptedPacketLength);
        MaxPacketLength = maxPacketLength;
    }

    /// <summary>
    /// Gets the largest packet_length field value the decoder accepts. Packets whose declared
    /// length exceeds this are rejected with SSH_DISCONNECT_PROTOCOL_ERROR before buffering.
    /// </summary>
    public int MaxPacketLength { get; }
}
