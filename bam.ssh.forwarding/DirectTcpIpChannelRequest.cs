using Bam.Ssh.Connection;

namespace Bam.Ssh.Forwarding;

/// <summary>
/// The <c>direct-tcpip</c> channel-open record (RFC 4254 §7.2): the host and port the peer should connect to
/// and the originating client's address and port. A client builds one to open a tunnel (local/dynamic
/// forwarding); a server parses one from an inbound open to learn where to connect.
/// </summary>
public sealed class DirectTcpIpChannelRequest
{
    /// <summary>
    /// Initializes the record.
    /// </summary>
    /// <param name="host">The host to connect to.</param>
    /// <param name="port">The port to connect to.</param>
    /// <param name="originatorAddress">The originating client's address.</param>
    /// <param name="originatorPort">The originating client's port.</param>
    /// <exception cref="ArgumentException">The host is null or empty.</exception>
    /// <exception cref="ArgumentNullException">The originator address is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">A port is outside 0–65535.</exception>
    public DirectTcpIpChannelRequest(string host, int port, string originatorAddress, int originatorPort)
    {
        ArgumentException.ThrowIfNullOrEmpty(host);
        ArgumentNullException.ThrowIfNull(originatorAddress);
        ForwardingPort.Validate(port);
        ForwardingPort.Validate(originatorPort);
        Host = host;
        Port = port;
        OriginatorAddress = originatorAddress;
        OriginatorPort = originatorPort;
    }

    /// <summary>
    /// Gets the host to connect to.
    /// </summary>
    public string Host { get; }

    /// <summary>
    /// Gets the port to connect to.
    /// </summary>
    public int Port { get; }

    /// <summary>
    /// Gets the originating client's address.
    /// </summary>
    public string OriginatorAddress { get; }

    /// <summary>
    /// Gets the originating client's port.
    /// </summary>
    public int OriginatorPort { get; }

    /// <summary>
    /// Encodes the record as the channel-type-specific bytes that follow the common channel-open fields.
    /// </summary>
    /// <returns>The encoded bytes.</returns>
    public ReadOnlyMemory<byte> ToTypeSpecificData()
    {
        using PooledBufferWriter writer = new PooledBufferWriter(24 + Host.Length + OriginatorAddress.Length);
        SshWireWriter wire = new SshWireWriter(writer);
        wire.WriteText(Host);
        wire.WriteUInt32((uint)Port);
        wire.WriteText(OriginatorAddress);
        wire.WriteUInt32((uint)OriginatorPort);
        return writer.WrittenSpan.ToArray();
    }

    /// <summary>
    /// Builds the full <c>direct-tcpip</c> channel-open parameters using the given connection options for the
    /// window and packet size.
    /// </summary>
    /// <param name="options">The connection options supplying the window and packet size.</param>
    /// <returns>The channel-open parameters.</returns>
    /// <exception cref="ArgumentNullException">The options are null.</exception>
    public SshChannelOpenParameters ToChannelOpenParameters(SshConnectionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        return new SshChannelOpenParameters(
            SshForwardingNames.DirectTcpIp, options.InitialWindowSize, options.MaximumPacketSize, ToTypeSpecificData());
    }

    /// <summary>
    /// Parses a <c>direct-tcpip</c> record from the channel-type-specific bytes.
    /// </summary>
    /// <param name="typeSpecificData">The bytes following the common channel-open fields.</param>
    /// <returns>The parsed record.</returns>
    /// <exception cref="SshForwardingException">The bytes are malformed.</exception>
    public static DirectTcpIpChannelRequest Parse(ReadOnlySpan<byte> typeSpecificData)
    {
        try
        {
            SshWireReader reader = new SshWireReader(typeSpecificData);
            string host = reader.ReadText();
            uint port = reader.ReadUInt32();
            string originator = reader.ReadText();
            uint originatorPort = reader.ReadUInt32();
            return new DirectTcpIpChannelRequest(host, (int)port, originator, (int)originatorPort);
        }
        catch (SshWireFormatException exception)
        {
            throw new SshForwardingException("The direct-tcpip channel record is malformed.", exception);
        }
        catch (ArgumentException exception)
        {
            throw new SshForwardingException("The direct-tcpip channel record is malformed.", exception);
        }
    }
}
