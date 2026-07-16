namespace Bam.Ssh.Connection;

/// <summary>
/// Decides what to do with a peer-initiated SSH_MSG_CHANNEL_OPEN. Supplied to an <see cref="SshConnection"/>
/// so it can act as a server (or otherwise accept inbound channels); when no handler is set, inbound opens
/// are rejected. The handler runs on the connection's dispatch loop, so it must not block — accept (or
/// reject) the channel and hand any real work to a separate task, otherwise the connection stalls.
/// </summary>
public interface ISshChannelOpenHandler
{
    /// <summary>
    /// Handles an inbound channel-open request by calling <see cref="SshChannelOpenRequestContext.Accept"/>
    /// or <see cref="SshChannelOpenRequestContext.Reject"/> on the context. If neither is called, the
    /// connection rejects the open with <see cref="SshChannelOpenFailureReason.UnknownChannelType"/>.
    /// </summary>
    /// <param name="context">The inbound open request and the accept/reject controls.</param>
    /// <param name="cancellationToken">Cancels the handling.</param>
    ValueTask HandleOpenAsync(SshChannelOpenRequestContext context, CancellationToken cancellationToken);
}
