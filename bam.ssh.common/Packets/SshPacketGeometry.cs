namespace Bam.Ssh;

/// <summary>
/// The cipher-dependent parameters that shape RFC 4253 §6 packet framing. Padding must bring the
/// packet to a multiple of the cipher block size (or 8, whichever is larger); which bytes count
/// toward that alignment depends on whether the packet_length field is encrypted — classic
/// ciphers encrypt it, while AEAD and encrypt-then-MAC modes (Phase 4) exclude the 4-byte length
/// field from the aligned region. This type is the seam that lets those modes alter framing
/// without changing the encoder.
/// </summary>
public readonly struct SshPacketGeometry
{
    /// <summary>
    /// The RFC 4253 §6 minimum padding length: every packet carries at least four padding bytes.
    /// </summary>
    public const int MinimumPaddingLength = 4;

    /// <summary>
    /// The RFC 4253 §6 floor for the alignment multiple: max(8, cipher block size).
    /// </summary>
    public const int MinimumBlockSize = 8;

    private readonly int _blockSize;

    /// <summary>
    /// The geometry used before any keys are negotiated (and by ciphers with 8-byte blocks):
    /// 8-byte alignment with the length field inside the encrypted region.
    /// </summary>
    public static readonly SshPacketGeometry Default = new SshPacketGeometry(MinimumBlockSize, true);

    /// <summary>
    /// Initializes a geometry for a cipher.
    /// </summary>
    /// <param name="blockSize">The cipher block size in bytes. Values below 8 are raised to 8 per the RFC; must be between 1 and 64.</param>
    /// <param name="lengthIsEncrypted">True when the packet_length field is inside the encrypted region (classic modes); false for AEAD and encrypt-then-MAC modes where the length field is excluded from padding alignment.</param>
    /// <exception cref="ArgumentOutOfRangeException">The block size is not between 1 and 64.</exception>
    public SshPacketGeometry(int blockSize, bool lengthIsEncrypted)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(blockSize, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(blockSize, 64);
        _blockSize = Math.Max(MinimumBlockSize, blockSize);
        LengthIsEncrypted = lengthIsEncrypted;
    }

    /// <summary>
    /// Gets the padding alignment multiple: max(8, cipher block size).
    /// A default-constructed instance yields 8.
    /// </summary>
    public int BlockSize => _blockSize == 0 ? MinimumBlockSize : _blockSize;

    /// <summary>
    /// Gets whether the packet_length field participates in padding alignment. True for classic
    /// ciphers (the whole packet is encrypted); false for AEAD/ETM modes, which align only
    /// padding_length + payload + padding.
    /// </summary>
    public bool LengthIsEncrypted { get; }
}
