namespace Bam.Ssh.Connection;

/// <summary>
/// The outcome of a global request sent with a reply requested (RFC 4254 §4): whether the peer replied
/// SSH_MSG_REQUEST_SUCCESS and the request-specific reply bytes that followed it (for example the bound
/// port a <c>tcpip-forward</c> with port 0 returns). <see cref="Data"/> is empty on failure.
/// </summary>
public sealed class SshGlobalRequestReply
{
    /// <summary>
    /// Initializes the reply.
    /// </summary>
    /// <param name="success">Whether the peer replied success.</param>
    /// <param name="data">The request-specific reply bytes (empty on failure).</param>
    public SshGlobalRequestReply(bool success, ReadOnlyMemory<byte> data)
    {
        Success = success;
        Data = data;
    }

    /// <summary>
    /// Gets whether the peer replied SSH_MSG_REQUEST_SUCCESS.
    /// </summary>
    public bool Success { get; }

    /// <summary>
    /// Gets the request-specific reply bytes that followed the success reply (empty on failure).
    /// </summary>
    public ReadOnlyMemory<byte> Data { get; }
}
