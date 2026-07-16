namespace Bam.Ssh.Transport;

/// <summary>
/// A source of decoded inbound SSH packets. <see cref="SshTransport"/> is the primary implementation
/// (reading directly from the wire), but the connection layer supplies an alternate implementation
/// during a loop-driven re-key: its single receive-dispatch loop remains the only reader of the
/// transport and forwards the key-exchange packets it sees to an <see cref="SshPacketQueue"/>, which
/// the key-exchange routine then consumes through this seam instead of reading the transport itself.
/// </summary>
public interface ISshPacketSource
{
    /// <summary>
    /// Receives the next inbound packet. Ownership of the returned packet transfers to the caller,
    /// which must dispose it after parsing.
    /// </summary>
    /// <param name="cancellationToken">Cancels the receive.</param>
    /// <returns>The next decoded packet.</returns>
    ValueTask<SshIncomingPacket> ReceivePacketAsync(CancellationToken cancellationToken = default);
}
