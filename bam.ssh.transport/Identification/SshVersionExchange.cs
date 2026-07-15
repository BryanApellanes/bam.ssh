using System.Buffers;
using System.IO.Pipelines;
using System.Text;

namespace Bam.Ssh.Transport;

/// <summary>
/// Performs the RFC 4253 §4.2 identification-string exchange over an <see cref="ISshDuplexStream"/>:
/// writes the local <c>SSH-2.0-...</c> line, then reads lines from the peer, tolerating any
/// pre-identification banner lines (which do not begin with <c>SSH-</c>) up to the configured cap,
/// until the peer's identification line arrives. Bounds every line and the banner count so a peer
/// cannot exhaust memory before the packet protocol starts. Stateless beyond its injected
/// dependencies; one exchange per connection.
/// </summary>
public sealed class SshVersionExchange
{
    private const byte CarriageReturn = 0x0D;
    private const byte LineFeed = 0x0A;

    private readonly ISshDuplexStream _stream;
    private readonly SshTransportOptions _options;

    /// <summary>
    /// Initializes a version exchange over the given transport with the given options.
    /// </summary>
    /// <param name="stream">The byte transport to exchange identification strings over.</param>
    /// <param name="options">The transport options bounding the exchange.</param>
    /// <exception cref="ArgumentNullException">A dependency is null.</exception>
    public SshVersionExchange(ISshDuplexStream stream, SshTransportOptions options)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(options);
        _stream = stream;
        _options = options;
    }

    /// <summary>
    /// Sends the local identification string and reads the peer's, skipping banner lines.
    /// </summary>
    /// <param name="local">The local identification string to advertise.</param>
    /// <param name="cancellationToken">Cancels the exchange.</param>
    /// <returns>Both identification strings and their raw bytes for the exchange hash.</returns>
    /// <exception cref="SshTransportException">The peer's identification is malformed, over-length, absent within the banner cap, or the stream ended early.</exception>
    public async ValueTask<SshVersionExchangeResult> ExchangeAsync(SshIdentificationString local, CancellationToken cancellationToken = default)
    {
        byte[] localBytes = local.ToWireBytes();
        await _stream.Output.WriteAsync(localBytes, cancellationToken).ConfigureAwait(false);
        await _stream.Output.FlushAsync(cancellationToken).ConfigureAwait(false);

        int bannerLines = 0;
        while (true)
        {
            string line = await ReadLineAsync(cancellationToken).ConfigureAwait(false);
            if (SshIdentificationString.TryParse(line, out SshIdentificationString remote))
            {
                if (!remote.IsProtocolSupported)
                {
                    throw new SshTransportException(
                        $"The peer advertised unsupported SSH protocol version '{remote.ProtocolVersion}'.",
                        SshDisconnectReason.ProtocolVersionNotSupported);
                }
                byte[] localRaw = Encoding.ASCII.GetBytes(local.ToString());
                byte[] remoteRaw = Encoding.ASCII.GetBytes(line);
                return new SshVersionExchangeResult(local, remote, localRaw, remoteRaw);
            }

            bannerLines++;
            if (bannerLines > _options.MaxBannerLines)
            {
                throw new SshTransportException(
                    $"The peer sent more than {_options.MaxBannerLines} banner lines without an identification string.",
                    SshDisconnectReason.ProtocolError);
            }
        }
    }

    private async ValueTask<string> ReadLineAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            ReadResult read = await _stream.Input.ReadAsync(cancellationToken).ConfigureAwait(false);
            ReadOnlySequence<byte> buffer = read.Buffer;

            if (TryReadLine(ref buffer, out string line))
            {
                _stream.Input.AdvanceTo(buffer.Start);
                return line;
            }

            if (buffer.Length > _options.MaxIdentificationLineLength + 2)
            {
                throw new SshTransportException(
                    $"An identification line exceeded {_options.MaxIdentificationLineLength} bytes without a line terminator.",
                    SshDisconnectReason.ProtocolError);
            }

            _stream.Input.AdvanceTo(buffer.Start, buffer.End);

            if (read.IsCompleted)
            {
                throw new SshTransportException(
                    "The stream ended before the peer sent a complete identification string.",
                    SshDisconnectReason.ConnectionLost);
            }
        }
    }

    private string TryReadLineOrThrowLength(ReadOnlySequence<byte> lineBytes)
    {
        if (lineBytes.Length > _options.MaxIdentificationLineLength)
        {
            throw new SshTransportException(
                $"An identification line of {lineBytes.Length} bytes exceeded the {_options.MaxIdentificationLineLength}-byte limit.",
                SshDisconnectReason.ProtocolError);
        }
        return Encoding.ASCII.GetString(lineBytes);
    }

    private bool TryReadLine(ref ReadOnlySequence<byte> buffer, out string line)
    {
        SequenceReader<byte> reader = new SequenceReader<byte>(buffer);
        if (reader.TryReadTo(out ReadOnlySequence<byte> lineBytes, LineFeed, advancePastDelimiter: true))
        {
            lineBytes = TrimTrailingCarriageReturn(lineBytes);
            line = TryReadLineOrThrowLength(lineBytes);
            buffer = buffer.Slice(reader.Position);
            return true;
        }
        line = string.Empty;
        return false;
    }

    private static ReadOnlySequence<byte> TrimTrailingCarriageReturn(ReadOnlySequence<byte> lineBytes)
    {
        if (lineBytes.Length == 0)
        {
            return lineBytes;
        }
        ReadOnlySequence<byte> lastByte = lineBytes.Slice(lineBytes.Length - 1);
        if (lastByte.FirstSpan[0] == CarriageReturn)
        {
            return lineBytes.Slice(0, lineBytes.Length - 1);
        }
        return lineBytes;
    }
}
