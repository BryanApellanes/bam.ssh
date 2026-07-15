namespace Bam.Ssh;

/// <summary>
/// A per-direction SSH packet sequence number (RFC 4253 §6.4): starts at zero, increments once
/// per packet, and wraps to zero after 2³²−1. Never reset, even when keys are renegotiated.
/// The MAC for a packet is computed over the sequence number the packet was sent with —
/// call <see cref="Advance"/> to obtain that number and move to the next.
/// This is a mutable struct: store it in a field (one per direction), never in a readonly
/// field or property, or the mutation will act on a copy.
/// </summary>
public struct SshSequenceNumber
{
    private uint _value;

    /// <summary>
    /// Initializes a sequence number at an arbitrary starting value. Protocol use always starts
    /// at zero (the default); this constructor exists for tests and diagnostics that need to
    /// exercise behavior near the wrap boundary.
    /// </summary>
    /// <param name="value">The starting sequence number.</param>
    public SshSequenceNumber(uint value)
    {
        _value = value;
    }

    /// <summary>
    /// Gets the sequence number the next packet will use.
    /// </summary>
    public readonly uint Value => _value;

    /// <summary>
    /// Returns the sequence number for the current packet and advances to the next,
    /// wrapping to zero after <see cref="uint.MaxValue"/>.
    /// </summary>
    /// <returns>The sequence number assigned to the packet being processed.</returns>
    public uint Advance()
    {
        uint current = _value;
        _value = unchecked(_value + 1);
        return current;
    }
}
