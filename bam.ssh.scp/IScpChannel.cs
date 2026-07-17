namespace Bam.Ssh.Scp;

/// <summary>
/// The narrow byte-stream seam the SCP protocol rides: read the peer's bytes and write bytes back. Both the
/// client's <c>SshChannel</c> (its data stream, via <see cref="SshChannelScpChannel"/>) and the server's
/// <c>SshServerCommandContext</c> satisfy this shape, so the SCP protocol code stays decoupled from the
/// client and server façades. Read returns zero at end of stream, matching stream semantics.
/// </summary>
public interface IScpChannel
{
    /// <summary>
    /// Reads bytes from the peer into the buffer.
    /// </summary>
    /// <param name="buffer">The destination buffer.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>The number of bytes read, or zero at end of stream.</returns>
    ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default);

    /// <summary>
    /// Writes bytes to the peer.
    /// </summary>
    /// <param name="data">The bytes to write.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    ValueTask WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default);
}
