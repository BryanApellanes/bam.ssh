using System.Buffers;
using System.IO.Pipelines;

namespace Bam.Ssh.Transport;

/// <summary>
/// Reads, authenticates, and de-frames one direction's inbound SSH packets. Owns the Phase 1
/// <see cref="SshPacketDecoder"/>, the inbound <see cref="ISshPacketCipher"/>, the receive
/// <see cref="SshSequenceNumber"/>, and the transport's <see cref="PipeReader"/>. Each read peeks
/// and decrypts the length exactly once, buffers the full wire packet, verifies and decrypts it,
/// de-frames the payload, and returns an owned <see cref="SshIncomingPacket"/>. Not thread-safe:
/// a connection reads from one logical reader.
/// </summary>
public sealed class SshPacketReader
{
    private readonly PipeReader _input;
    private readonly SshPacketDecoder _decoder;
    private readonly SshPacketLimits _limits;
    private ISshPacketCipher _cipher;
    private SshSequenceNumber _sequence;

    /// <summary>
    /// Initializes a reader over the given pipe with the given cipher and limits.
    /// </summary>
    /// <param name="input">The transport pipe reader delivering inbound bytes.</param>
    /// <param name="cipher">The initial inbound cipher (typically <see cref="NonePacketCipher.Instance"/>).</param>
    /// <param name="limits">The packet limits to enforce; defaults to <see cref="SshPacketLimits.Default"/>.</param>
    /// <exception cref="ArgumentNullException">A required dependency is null.</exception>
    public SshPacketReader(PipeReader input, ISshPacketCipher cipher, SshPacketLimits? limits = null)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(cipher);
        _input = input;
        _cipher = cipher;
        _limits = limits ?? SshPacketLimits.Default;
        _decoder = new SshPacketDecoder(_limits);
        _sequence = new SshSequenceNumber();
    }

    /// <summary>
    /// Gets the sequence number the next received packet will use.
    /// </summary>
    public uint NextSequenceNumber => _sequence.Value;

    /// <summary>
    /// Replaces the inbound cipher, effective for the next packet — the transport calls this when
    /// SSH_MSG_NEWKEYS activates newly negotiated keys. The sequence number is not reset.
    /// </summary>
    /// <param name="cipher">The new inbound cipher.</param>
    /// <exception cref="ArgumentNullException">The cipher is null.</exception>
    public void SwapCipher(ISshPacketCipher cipher)
    {
        ArgumentNullException.ThrowIfNull(cipher);
        _cipher = cipher;
    }

    /// <summary>
    /// Reads one complete packet: buffers the wire bytes, authenticates and decrypts them,
    /// de-frames the payload, and returns it in an owned pooled buffer.
    /// </summary>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>The decoded packet payload; dispose it after parsing.</returns>
    /// <exception cref="SshTransportException">The stream ended mid-packet or MAC verification failed.</exception>
    /// <exception cref="SshPacketFormatException">The frame violated the protocol's structural rules.</exception>
    public async ValueTask<SshIncomingPacket> ReadAsync(CancellationToken cancellationToken = default)
    {
        int lengthPeekSize = _cipher.LengthPeekSize;
        int macLength = _cipher.MacLength;
        bool lengthKnown = false;
        uint packetLength = 0;
        int totalWireLength = 0;

        while (true)
        {
            ReadResult read = await _input.ReadAsync(cancellationToken).ConfigureAwait(false);
            ReadOnlySequence<byte> buffer = read.Buffer;

            if (!lengthKnown)
            {
                if (buffer.Length < lengthPeekSize)
                {
                    if (read.IsCompleted)
                    {
                        throw EndOfStream(buffer.Length);
                    }
                    _input.AdvanceTo(buffer.Start, buffer.End);
                    continue;
                }

                Span<byte> peek = stackalloc byte[lengthPeekSize];
                buffer.Slice(0, lengthPeekSize).CopyTo(peek);
                Span<byte> decryptedLength = stackalloc byte[4];
                packetLength = _cipher.DecryptLength(peek, _sequence.Value, decryptedLength);
                ValidatePacketLength(packetLength);
                totalWireLength = checked(4 + (int)packetLength + macLength);
                lengthKnown = true;
            }

            if (buffer.Length < totalWireLength)
            {
                if (read.IsCompleted)
                {
                    throw EndOfStream(buffer.Length);
                }
                _input.AdvanceTo(buffer.Start, buffer.End);
                continue;
            }

            ReadOnlySequence<byte> wirePacket = buffer.Slice(0, totalWireLength);
            SshIncomingPacket packet = DecryptAndDeframe(wirePacket, packetLength);
            _input.AdvanceTo(buffer.GetPosition(totalWireLength));
            return packet;
        }
    }

    private SshIncomingPacket DecryptAndDeframe(ReadOnlySequence<byte> wirePacket, uint packetLength)
    {
        uint sequenceNumber = _sequence.Advance();

        using PooledBufferWriter cleartext = new PooledBufferWriter(4 + (int)packetLength);
        bool authenticated;
        if (wirePacket.IsSingleSegment)
        {
            authenticated = _cipher.VerifyAndDecrypt(wirePacket.FirstSpan, sequenceNumber, cleartext);
        }
        else
        {
            using SshRentedBuffer contiguous = SshRentedBuffer.Rent((int)wirePacket.Length);
            wirePacket.CopyTo(contiguous.Span);
            authenticated = _cipher.VerifyAndDecrypt(contiguous.Span, sequenceNumber, cleartext);
        }

        if (!authenticated)
        {
            throw new SshTransportException(
                "Message authentication failed for an incoming packet.",
                SshDisconnectReason.MacError);
        }

        ReadOnlySequence<byte> framed = new ReadOnlySequence<byte>(cleartext.WrittenMemory);
        if (!_decoder.TryDecode(ref framed, out SshPacketFrame frame))
        {
            throw new SshTransportException(
                "A decrypted packet did not contain a complete frame.",
                SshDisconnectReason.ProtocolError);
        }

        int payloadLength = (int)frame.Payload.Length;
        SshRentedBuffer payloadBuffer = SshRentedBuffer.Rent(payloadLength);
        frame.Payload.CopyTo(payloadBuffer.Span);
        return new SshIncomingPacket(payloadBuffer, payloadLength);
    }

    private void ValidatePacketLength(uint packetLength)
    {
        if (packetLength < SshPacketLimits.MinimumPacketLength)
        {
            throw new SshPacketFormatException(
                $"Declared packet_length {packetLength} is below the protocol minimum.",
                SshDisconnectReason.ProtocolError);
        }
        if (packetLength > (uint)_limits.MaxPacketLength)
        {
            throw new SshPacketFormatException(
                $"Declared packet_length {packetLength} exceeds the configured maximum of {_limits.MaxPacketLength}.",
                SshDisconnectReason.ProtocolError);
        }
    }

    private static SshTransportException EndOfStream(long bufferedBytes)
    {
        return new SshTransportException(
            $"The stream ended with {bufferedBytes} bytes buffered, mid-packet.",
            SshDisconnectReason.ConnectionLost);
    }
}
