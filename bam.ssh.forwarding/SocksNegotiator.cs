using System.Net;
using System.Text;

namespace Bam.Ssh.Forwarding;

/// <summary>
/// Performs the SOCKS handshake a dynamic (<c>-D</c>) forwarder speaks with its local client to learn the
/// tunnel destination. Supports SOCKS5 (no-authentication) and SOCKS4/4a, CONNECT command only. A single
/// negotiator handles one connection: <see cref="NegotiateAsync"/> reads the request and returns the
/// destination, then <see cref="WriteSuccessReplyAsync"/> or <see cref="WriteFailureReplyAsync"/> writes the
/// version-appropriate reply once the tunnel is (or is not) established.
/// </summary>
public sealed class SocksNegotiator
{
    private const byte Socks5 = 0x05;
    private const byte Socks4 = 0x04;
    private const byte CommandConnect = 0x01;
    private const byte Socks5NoAuth = 0x00;
    private const byte Socks5NoAcceptableMethods = 0xFF;
    private const byte Socks4Granted = 0x5A;
    private const byte Socks4Rejected = 0x5B;

    private byte _version;

    /// <summary>
    /// Reads and parses the SOCKS request, returning the destination the client wants to reach. For SOCKS5
    /// the method-selection reply (no-auth) is written as part of this exchange.
    /// </summary>
    /// <param name="stream">The client byte stream.</param>
    /// <param name="cancellationToken">Cancels the negotiation.</param>
    /// <returns>The negotiated destination.</returns>
    /// <exception cref="ArgumentNullException">The stream is null.</exception>
    /// <exception cref="SshForwardingException">The version is unsupported or the request is malformed.</exception>
    public async ValueTask<SocksTarget> NegotiateAsync(Stream stream, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        _version = await ReadByteAsync(stream, cancellationToken).ConfigureAwait(false);
        return _version switch
        {
            Socks5 => await NegotiateSocks5Async(stream, cancellationToken).ConfigureAwait(false),
            Socks4 => await NegotiateSocks4Async(stream, cancellationToken).ConfigureAwait(false),
            _ => throw new SshForwardingException($"Unsupported SOCKS version {_version}."),
        };
    }

    /// <summary>
    /// Writes the reply that tells the client the tunnel is established.
    /// </summary>
    /// <param name="stream">The client byte stream.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    public ValueTask WriteSuccessReplyAsync(Stream stream, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        return WriteReplyAsync(stream, true, cancellationToken);
    }

    /// <summary>
    /// Writes the reply that tells the client the tunnel could not be established.
    /// </summary>
    /// <param name="stream">The client byte stream.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    public ValueTask WriteFailureReplyAsync(Stream stream, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        return WriteReplyAsync(stream, false, cancellationToken);
    }

    private async ValueTask<SocksTarget> NegotiateSocks5Async(Stream stream, CancellationToken cancellationToken)
    {
        byte methodCount = await ReadByteAsync(stream, cancellationToken).ConfigureAwait(false);
        byte[] methods = new byte[methodCount];
        await ReadExactAsync(stream, methods, cancellationToken).ConfigureAwait(false);
        bool noAuthOffered = Array.IndexOf(methods, Socks5NoAuth) >= 0;

        byte[] methodReply = new byte[] { Socks5, noAuthOffered ? Socks5NoAuth : Socks5NoAcceptableMethods };
        await stream.WriteAsync(methodReply, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        if (!noAuthOffered)
        {
            throw new SshForwardingException("The SOCKS5 client offered no no-authentication method.");
        }

        byte[] header = new byte[4];
        await ReadExactAsync(stream, header, cancellationToken).ConfigureAwait(false);
        if (header[0] != Socks5)
        {
            throw new SshForwardingException("Malformed SOCKS5 request header.");
        }
        if (header[1] != CommandConnect)
        {
            throw new SshForwardingException($"Unsupported SOCKS5 command {header[1]} (only CONNECT is supported).");
        }

        byte addressType = header[3];
        string host;
        switch (addressType)
        {
            case 0x01:
                byte[] ipv4 = new byte[4];
                await ReadExactAsync(stream, ipv4, cancellationToken).ConfigureAwait(false);
                host = new IPAddress(ipv4).ToString();
                break;
            case 0x03:
                byte length = await ReadByteAsync(stream, cancellationToken).ConfigureAwait(false);
                byte[] name = new byte[length];
                await ReadExactAsync(stream, name, cancellationToken).ConfigureAwait(false);
                host = Encoding.ASCII.GetString(name);
                break;
            case 0x04:
                byte[] ipv6 = new byte[16];
                await ReadExactAsync(stream, ipv6, cancellationToken).ConfigureAwait(false);
                host = new IPAddress(ipv6).ToString();
                break;
            default:
                throw new SshForwardingException($"Unsupported SOCKS5 address type {addressType}.");
        }

        byte[] portBytes = new byte[2];
        await ReadExactAsync(stream, portBytes, cancellationToken).ConfigureAwait(false);
        int port = (portBytes[0] << 8) | portBytes[1];
        return new SocksTarget(host, port);
    }

    private async ValueTask<SocksTarget> NegotiateSocks4Async(Stream stream, CancellationToken cancellationToken)
    {
        byte command = await ReadByteAsync(stream, cancellationToken).ConfigureAwait(false);
        if (command != CommandConnect)
        {
            throw new SshForwardingException($"Unsupported SOCKS4 command {command} (only CONNECT is supported).");
        }

        byte[] portBytes = new byte[2];
        await ReadExactAsync(stream, portBytes, cancellationToken).ConfigureAwait(false);
        int port = (portBytes[0] << 8) | portBytes[1];

        byte[] ipv4 = new byte[4];
        await ReadExactAsync(stream, ipv4, cancellationToken).ConfigureAwait(false);

        // User id, null-terminated (ignored).
        await ReadNullTerminatedAsync(stream, cancellationToken).ConfigureAwait(false);

        bool isSocks4a = ipv4[0] == 0 && ipv4[1] == 0 && ipv4[2] == 0 && ipv4[3] != 0;
        string host = isSocks4a
            ? await ReadNullTerminatedAsync(stream, cancellationToken).ConfigureAwait(false)
            : new IPAddress(ipv4).ToString();
        if (string.IsNullOrEmpty(host))
        {
            throw new SshForwardingException("The SOCKS4a request carried an empty host name.");
        }
        return new SocksTarget(host, port);
    }

    private async ValueTask WriteReplyAsync(Stream stream, bool success, CancellationToken cancellationToken)
    {
        byte[] reply;
        if (_version == Socks5)
        {
            // ver, rep (0 success / 1 general failure), rsv, atyp=IPv4, bnd.addr 0.0.0.0, bnd.port 0.
            reply = new byte[] { Socks5, success ? (byte)0x00 : (byte)0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0 };
        }
        else
        {
            // null, status, dstport (2), dstip (4).
            reply = new byte[] { 0x00, success ? Socks4Granted : Socks4Rejected, 0, 0, 0, 0, 0, 0 };
        }
        await stream.WriteAsync(reply, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<byte> ReadByteAsync(Stream stream, CancellationToken cancellationToken)
    {
        byte[] one = new byte[1];
        await ReadExactAsync(stream, one, cancellationToken).ConfigureAwait(false);
        return one[0];
    }

    private static async ValueTask ReadExactAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        int offset = 0;
        while (offset < buffer.Length)
        {
            int read = await stream.ReadAsync(buffer.AsMemory(offset), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new SshForwardingException("The SOCKS client closed the connection during negotiation.");
            }
            offset += read;
        }
    }

    private static async ValueTask<string> ReadNullTerminatedAsync(Stream stream, CancellationToken cancellationToken)
    {
        StringBuilder builder = new StringBuilder();
        byte[] one = new byte[1];
        while (true)
        {
            int read = await stream.ReadAsync(one.AsMemory(0, 1), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new SshForwardingException("The SOCKS client closed the connection during negotiation.");
            }
            if (one[0] == 0)
            {
                return builder.ToString();
            }
            builder.Append((char)one[0]);
        }
    }
}
