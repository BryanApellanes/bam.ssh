using System.Buffers;
using System.IO.Pipelines;

namespace Bam.Ssh.Transport;

/// <summary>
/// Frames and sends one direction's outbound SSH packets. Owns the Phase 1
/// <see cref="SshPacketEncoder"/>, the outbound <see cref="ISshPacketCipher"/>, the send
/// <see cref="SshSequenceNumber"/>, and the transport's <see cref="PipeWriter"/>. Each call encodes
/// the payload into a framed packet (padding aligned to the cipher's geometry), transforms it
/// through the cipher (identity until Phase 4), writes it to the pipe, and advances the sequence
/// number. Not thread-safe: a single connection sends from one logical writer; callers serialize.
/// </summary>
public sealed class SshPacketWriter
{
    private readonly SshPacketEncoder _encoder;
    private readonly PipeWriter _output;
    // Reused across packets (this writer is single-threaded; callers serialize) so framing does not allocate
    // a wrapper per packet — the underlying pooled buffer grows to the largest packet and is then reused.
    private readonly PooledBufferWriter _framed = new PooledBufferWriter();
    private ISshPacketCipher _cipher;
    private SshSequenceNumber _sequence;

    /// <summary>
    /// Initializes a writer over the given pipe with the given cipher.
    /// </summary>
    /// <param name="output">The transport pipe writer to send framed packets to.</param>
    /// <param name="cipher">The initial outbound cipher (typically <see cref="NonePacketCipher.Instance"/>).</param>
    /// <param name="encoder">The packet encoder; defaults to a new encoder over the secure random source.</param>
    /// <exception cref="ArgumentNullException">A required dependency is null.</exception>
    public SshPacketWriter(PipeWriter output, ISshPacketCipher cipher, SshPacketEncoder? encoder = null)
    {
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(cipher);
        _output = output;
        _cipher = cipher;
        _encoder = encoder ?? new SshPacketEncoder();
        _sequence = new SshSequenceNumber();
    }

    /// <summary>
    /// Gets the sequence number the next sent packet will use.
    /// </summary>
    public uint NextSequenceNumber => _sequence.Value;

    /// <summary>
    /// Replaces the outbound cipher, effective for the next packet — the transport calls this when
    /// SSH_MSG_NEWKEYS activates newly negotiated keys. The sequence number is not reset.
    /// </summary>
    /// <param name="cipher">The new outbound cipher.</param>
    /// <exception cref="ArgumentNullException">The cipher is null.</exception>
    public void SwapCipher(ISshPacketCipher cipher)
    {
        ArgumentNullException.ThrowIfNull(cipher);
        _cipher = cipher;
    }

    /// <summary>
    /// Frames, transforms, and sends a payload as one SSH packet, then flushes the transport pipe.
    /// </summary>
    /// <param name="payload">The packet payload (message number followed by message fields).</param>
    /// <param name="cancellationToken">Cancels the flush.</param>
    /// <returns>A task that completes when the packet has been written and flushed.</returns>
    public async ValueTask WriteAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken = default)
    {
        uint sequenceNumber = _sequence.Advance();

        _framed.Reset();
        _encoder.Encode(payload.Span, _framed, _cipher.Geometry);
        _cipher.TransformOutgoing(_framed.WrittenSpan, sequenceNumber, _output);

        await _output.FlushAsync(cancellationToken).ConfigureAwait(false);
    }
}
