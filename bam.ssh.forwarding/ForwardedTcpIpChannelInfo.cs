using Bam.Ssh.Connection;

namespace Bam.Ssh.Forwarding;

/// <summary>
/// The <c>forwarded-tcpip</c> channel-open record (RFC 4254 §7.2): the address and port the connection was
/// accepted on (the remote-forwarded bind) and the originating peer's address and port. A server builds one
/// when a connection arrives on a forwarded port; a client parses one to route the tunnel to the right local
/// target.
/// </summary>
public sealed class ForwardedTcpIpChannelInfo
{
    /// <summary>
    /// Initializes the record.
    /// </summary>
    /// <param name="connectedAddress">The bind address the connection was accepted on.</param>
    /// <param name="connectedPort">The bind port the connection was accepted on.</param>
    /// <param name="originatorAddress">The originating peer's address.</param>
    /// <param name="originatorPort">The originating peer's port.</param>
    /// <exception cref="ArgumentNullException">The connected or originator address is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">A port is outside 0–65535.</exception>
    public ForwardedTcpIpChannelInfo(string connectedAddress, int connectedPort, string originatorAddress, int originatorPort)
    {
        ArgumentNullException.ThrowIfNull(connectedAddress);
        ArgumentNullException.ThrowIfNull(originatorAddress);
        ForwardingPort.Validate(connectedPort);
        ForwardingPort.Validate(originatorPort);
        ConnectedAddress = connectedAddress;
        ConnectedPort = connectedPort;
        OriginatorAddress = originatorAddress;
        OriginatorPort = originatorPort;
    }

    /// <summary>
    /// Gets the bind address the connection was accepted on.
    /// </summary>
    public string ConnectedAddress { get; }

    /// <summary>
    /// Gets the bind port the connection was accepted on.
    /// </summary>
    public int ConnectedPort { get; }

    /// <summary>
    /// Gets the originating peer's address.
    /// </summary>
    public string OriginatorAddress { get; }

    /// <summary>
    /// Gets the originating peer's port.
    /// </summary>
    public int OriginatorPort { get; }

    /// <summary>
    /// Encodes the record as the channel-type-specific bytes that follow the common channel-open fields.
    /// </summary>
    /// <returns>The encoded bytes.</returns>
    public ReadOnlyMemory<byte> ToTypeSpecificData()
    {
        using PooledBufferWriter writer = new PooledBufferWriter(24 + ConnectedAddress.Length + OriginatorAddress.Length);
        SshWireWriter wire = new SshWireWriter(writer);
        wire.WriteText(ConnectedAddress);
        wire.WriteUInt32((uint)ConnectedPort);
        wire.WriteText(OriginatorAddress);
        wire.WriteUInt32((uint)OriginatorPort);
        return writer.WrittenSpan.ToArray();
    }

    /// <summary>
    /// Builds the full <c>forwarded-tcpip</c> channel-open parameters using the given connection options for
    /// the window and packet size.
    /// </summary>
    /// <param name="options">The connection options supplying the window and packet size.</param>
    /// <returns>The channel-open parameters.</returns>
    /// <exception cref="ArgumentNullException">The options are null.</exception>
    public SshChannelOpenParameters ToChannelOpenParameters(SshConnectionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        return new SshChannelOpenParameters(
            SshForwardingNames.ForwardedTcpIp, options.InitialWindowSize, options.MaximumPacketSize, ToTypeSpecificData());
    }

    /// <summary>
    /// Parses a <c>forwarded-tcpip</c> record from the channel-type-specific bytes.
    /// </summary>
    /// <param name="typeSpecificData">The bytes following the common channel-open fields.</param>
    /// <returns>The parsed record.</returns>
    /// <exception cref="SshForwardingException">The bytes are malformed.</exception>
    public static ForwardedTcpIpChannelInfo Parse(ReadOnlySpan<byte> typeSpecificData)
    {
        try
        {
            SshWireReader reader = new SshWireReader(typeSpecificData);
            string connectedAddress = reader.ReadText();
            uint connectedPort = reader.ReadUInt32();
            string originator = reader.ReadText();
            uint originatorPort = reader.ReadUInt32();
            return new ForwardedTcpIpChannelInfo(connectedAddress, (int)connectedPort, originator, (int)originatorPort);
        }
        catch (SshWireFormatException exception)
        {
            throw new SshForwardingException("The forwarded-tcpip channel record is malformed.", exception);
        }
        catch (ArgumentException exception)
        {
            throw new SshForwardingException("The forwarded-tcpip channel record is malformed.", exception);
        }
    }
}
