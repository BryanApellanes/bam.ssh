namespace Bam.Ssh.Forwarding;

/// <summary>
/// The <c>tcpip-forward</c> / <c>cancel-tcpip-forward</c> global-request record (RFC 4254 §7.1): the address
/// and port the peer should bind (or stop binding). When the bind port is 0, the peer chooses a free port and
/// returns it in the SSH_MSG_REQUEST_SUCCESS reply — <see cref="BuildBoundPortReply"/> /
/// <see cref="ParseBoundPortReply"/> encode that reply.
/// </summary>
public sealed class TcpIpForwardRequest
{
    /// <summary>
    /// Initializes the record.
    /// </summary>
    /// <param name="bindAddress">The address to bind (empty or <c>0.0.0.0</c> for all interfaces).</param>
    /// <param name="bindPort">The port to bind (0 to let the peer choose).</param>
    /// <exception cref="ArgumentNullException">The bind address is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The port is outside 0–65535.</exception>
    public TcpIpForwardRequest(string bindAddress, int bindPort)
    {
        ArgumentNullException.ThrowIfNull(bindAddress);
        ForwardingPort.Validate(bindPort);
        BindAddress = bindAddress;
        BindPort = bindPort;
    }

    /// <summary>
    /// Gets the address to bind.
    /// </summary>
    public string BindAddress { get; }

    /// <summary>
    /// Gets the port to bind (0 to let the peer choose).
    /// </summary>
    public int BindPort { get; }

    /// <summary>
    /// Encodes the record as the request-specific bytes that follow the global-request name and reply flag.
    /// </summary>
    /// <returns>The encoded bytes.</returns>
    public ReadOnlyMemory<byte> ToRequestData()
    {
        using PooledBufferWriter writer = new PooledBufferWriter(8 + BindAddress.Length);
        SshWireWriter wire = new SshWireWriter(writer);
        wire.WriteText(BindAddress);
        wire.WriteUInt32((uint)BindPort);
        return writer.WrittenSpan.ToArray();
    }

    /// <summary>
    /// Parses a <c>tcpip-forward</c>/<c>cancel-tcpip-forward</c> record from the request-specific bytes.
    /// </summary>
    /// <param name="requestData">The bytes following the request name and reply flag.</param>
    /// <returns>The parsed record.</returns>
    /// <exception cref="SshForwardingException">The bytes are malformed.</exception>
    public static TcpIpForwardRequest Parse(ReadOnlySpan<byte> requestData)
    {
        try
        {
            SshWireReader reader = new SshWireReader(requestData);
            string bindAddress = reader.ReadText();
            uint bindPort = reader.ReadUInt32();
            return new TcpIpForwardRequest(bindAddress, (int)bindPort);
        }
        catch (SshWireFormatException exception)
        {
            throw new SshForwardingException("The tcpip-forward request is malformed.", exception);
        }
        catch (ArgumentException exception)
        {
            throw new SshForwardingException("The tcpip-forward request is malformed.", exception);
        }
    }

    /// <summary>
    /// Encodes the bound-port reply data for a <c>tcpip-forward</c> that requested port 0.
    /// </summary>
    /// <param name="boundPort">The port the peer actually bound.</param>
    /// <returns>The reply bytes.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The port is outside 0–65535.</exception>
    public static ReadOnlyMemory<byte> BuildBoundPortReply(int boundPort)
    {
        ForwardingPort.Validate(boundPort);
        using PooledBufferWriter writer = new PooledBufferWriter(4);
        SshWireWriter wire = new SshWireWriter(writer);
        wire.WriteUInt32((uint)boundPort);
        return writer.WrittenSpan.ToArray();
    }

    /// <summary>
    /// Parses the bound port from a <c>tcpip-forward</c> success reply.
    /// </summary>
    /// <param name="replyData">The reply bytes.</param>
    /// <returns>The bound port.</returns>
    /// <exception cref="SshForwardingException">The reply is malformed.</exception>
    public static int ParseBoundPortReply(ReadOnlySpan<byte> replyData)
    {
        try
        {
            SshWireReader reader = new SshWireReader(replyData);
            return (int)reader.ReadUInt32();
        }
        catch (SshWireFormatException exception)
        {
            throw new SshForwardingException("The tcpip-forward reply is malformed.", exception);
        }
    }
}
