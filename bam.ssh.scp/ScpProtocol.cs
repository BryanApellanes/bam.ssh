using System.Collections.Generic;
using System.Text;

namespace Bam.Ssh.Scp;

/// <summary>
/// The byte-level SCP grammar over an <see cref="IScpChannel"/>: single-byte acknowledgements (<c>0x00</c>
/// success, <c>0x01</c> warning, <c>0x02</c> fatal), newline-terminated control lines, and exact-length
/// reads for file data. Instances are single-flow (no concurrent calls) and reuse a one-byte scratch buffer.
/// </summary>
public sealed class ScpProtocol
{
    private const byte AckOk = 0x00;
    private const byte AckWarning = 0x01;
    private const byte AckFatal = 0x02;
    private const byte Newline = (byte)'\n';

    private readonly IScpChannel _channel;
    private readonly byte[] _oneByte = new byte[1];

    /// <summary>
    /// Initializes the helper over a channel.
    /// </summary>
    /// <param name="channel">The byte channel SCP rides.</param>
    /// <exception cref="ArgumentNullException">The channel is null.</exception>
    public ScpProtocol(IScpChannel channel)
    {
        ArgumentNullException.ThrowIfNull(channel);
        _channel = channel;
    }

    /// <summary>
    /// Writes a success acknowledgement (<c>0x00</c>).
    /// </summary>
    /// <param name="cancellationToken">Cancels the write.</param>
    public ValueTask WriteAckAsync(CancellationToken cancellationToken = default)
    {
        byte[] ack = new byte[1];
        ack[0] = AckOk;
        return _channel.WriteAsync(ack, cancellationToken);
    }

    /// <summary>
    /// Reads an acknowledgement and throws if the peer reported a warning or fatal error.
    /// </summary>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <exception cref="ScpException">The stream ended, or the peer sent a non-zero status.</exception>
    public async ValueTask ReadAckAsync(CancellationToken cancellationToken = default)
    {
        int status = await ReadByteAsync(cancellationToken).ConfigureAwait(false);
        if (status < 0)
        {
            throw new ScpException("The SCP stream ended while awaiting an acknowledgement.");
        }

        if (status == AckOk)
        {
            return;
        }

        if (status == AckWarning || status == AckFatal)
        {
            string message = await ReadLineTextAsync(cancellationToken).ConfigureAwait(false) ?? string.Empty;
            throw new ScpException($"The SCP peer reported an error: {message}");
        }

        throw new ScpException($"Unexpected SCP acknowledgement byte 0x{status:X2}.");
    }

    /// <summary>
    /// Writes a fatal error record (<c>0x02</c> followed by the message and a newline) so the peer aborts the
    /// transfer with the given reason.
    /// </summary>
    /// <param name="message">The error message (a newline is appended).</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <exception cref="ArgumentNullException">The message is null.</exception>
    public ValueTask WriteErrorAsync(string message, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);
        int byteCount = Encoding.UTF8.GetByteCount(message);
        byte[] buffer = new byte[byteCount + 2];
        buffer[0] = AckFatal;
        Encoding.UTF8.GetBytes(message, 0, message.Length, buffer, 1);
        buffer[byteCount + 1] = Newline;
        return _channel.WriteAsync(buffer, cancellationToken);
    }

    /// <summary>
    /// Writes a control line, appending the terminating newline.
    /// </summary>
    /// <param name="line">The control line without a trailing newline.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <exception cref="ArgumentNullException">The line is null.</exception>
    public ValueTask WriteLineAsync(string line, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(line);
        int byteCount = Encoding.UTF8.GetByteCount(line);
        byte[] buffer = new byte[byteCount + 1];
        Encoding.UTF8.GetBytes(line, 0, line.Length, buffer, 0);
        buffer[byteCount] = Newline;
        return _channel.WriteAsync(buffer, cancellationToken);
    }

    /// <summary>
    /// Reads the next control line (without its newline), or null at end of stream.
    /// </summary>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>The control line, or null if the stream ended before any byte was read.</returns>
    public ValueTask<string?> ReadControlLineAsync(CancellationToken cancellationToken = default)
    {
        return ReadLineTextAsync(cancellationToken);
    }

    /// <summary>
    /// Reads exactly <paramref name="buffer"/>.Length bytes, throwing if the stream ends first.
    /// </summary>
    /// <param name="buffer">The buffer to fill.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <exception cref="ScpException">The stream ended before the buffer was filled.</exception>
    public async ValueTask ReadExactAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        int offset = 0;
        while (offset < buffer.Length)
        {
            int read = await _channel.ReadAsync(buffer.Slice(offset), cancellationToken).ConfigureAwait(false);
            if (read <= 0)
            {
                throw new ScpException("The SCP stream ended while reading file data.");
            }

            offset += read;
        }
    }

    /// <summary>
    /// Writes raw bytes to the channel (used to stream file data).
    /// </summary>
    /// <param name="data">The bytes to write.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    public ValueTask WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
    {
        return _channel.WriteAsync(data, cancellationToken);
    }

    private async ValueTask<string?> ReadLineTextAsync(CancellationToken cancellationToken)
    {
        List<byte> bytes = new List<byte>(64);
        while (true)
        {
            int b = await ReadByteAsync(cancellationToken).ConfigureAwait(false);
            if (b < 0)
            {
                return bytes.Count == 0 ? null : Encoding.UTF8.GetString(bytes.ToArray());
            }

            if (b == Newline)
            {
                return Encoding.UTF8.GetString(bytes.ToArray());
            }

            bytes.Add((byte)b);
        }
    }

    private async ValueTask<int> ReadByteAsync(CancellationToken cancellationToken)
    {
        int read = await _channel.ReadAsync(_oneByte, cancellationToken).ConfigureAwait(false);
        return read <= 0 ? -1 : _oneByte[0];
    }
}
