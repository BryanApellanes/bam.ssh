using System.Buffers;
using System.Buffers.Binary;

namespace Bam.Ssh.Sftp;

/// <summary>
/// Frames SFTP messages over an <see cref="ISftpChannel"/>: every message is a big-endian <c>uint32</c>
/// length (of the type byte plus the payload) followed by the <see cref="SftpPacketType"/> and the payload.
/// Reads a whole message into a pooled buffer (guarding against an oversized length) and writes a message
/// as a single buffered write so concurrent callers never interleave. Reads and writes are each expected to
/// be serialized by the caller (the client's request lock, the server's single loop).
/// </summary>
public sealed class SftpMessageChannel
{
    /// <summary>The largest SFTP message accepted, guarding against a hostile or corrupt length.</summary>
    public const int MaximumMessageLength = 4 * 1024 * 1024;

    private readonly ISftpChannel _channel;
    private readonly byte[] _lengthBuffer = new byte[4];

    /// <summary>
    /// Initializes the framing over a byte channel.
    /// </summary>
    /// <param name="channel">The underlying byte channel.</param>
    /// <exception cref="ArgumentNullException">The channel is null.</exception>
    public SftpMessageChannel(ISftpChannel channel)
    {
        ArgumentNullException.ThrowIfNull(channel);
        _channel = channel;
    }

    /// <summary>
    /// Reads the next whole SFTP message. Dispose the returned message to return its pooled buffer.
    /// </summary>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>The parsed message.</returns>
    /// <exception cref="SftpException">The stream ended mid-message or the length exceeds the maximum.</exception>
    public async ValueTask<SftpMessage> ReadMessageAsync(CancellationToken cancellationToken = default)
    {
        await ReadExactlyAsync(_lengthBuffer, cancellationToken).ConfigureAwait(false);
        uint length = BinaryPrimitives.ReadUInt32BigEndian(_lengthBuffer);
        if (length == 0)
        {
            throw new SftpException("Received a zero-length SFTP message.");
        }
        if (length > MaximumMessageLength)
        {
            throw new SftpException($"SFTP message length {length} exceeds the maximum of {MaximumMessageLength}.");
        }

        byte[] rented = ArrayPool<byte>.Shared.Rent((int)length);
        try
        {
            await ReadExactlyAsync(rented.AsMemory(0, (int)length), cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            ArrayPool<byte>.Shared.Return(rented);
            throw;
        }
        return new SftpMessage((SftpPacketType)rented[0], rented, (int)length);
    }

    /// <summary>
    /// Writes one SFTP message (its type and payload) as a single length-prefixed frame.
    /// </summary>
    /// <param name="type">The message type.</param>
    /// <param name="payload">The already-serialized message payload (everything after the type byte).</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    public async ValueTask WriteMessageAsync(SftpPacketType type, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken = default)
    {
        int total = 4 + 1 + payload.Length;
        byte[] rented = ArrayPool<byte>.Shared.Rent(total);
        try
        {
            BinaryPrimitives.WriteUInt32BigEndian(rented.AsSpan(0, 4), (uint)(payload.Length + 1));
            rented[4] = (byte)type;
            payload.Span.CopyTo(rented.AsSpan(5));
            await _channel.WriteAsync(rented.AsMemory(0, total), cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    private async ValueTask ReadExactlyAsync(Memory<byte> buffer, CancellationToken cancellationToken)
    {
        int read = 0;
        while (read < buffer.Length)
        {
            int count = await _channel.ReadAsync(buffer.Slice(read), cancellationToken).ConfigureAwait(false);
            if (count == 0)
            {
                throw new SftpException("The SFTP stream ended before a full message was read.");
            }
            read += count;
        }
    }
}
