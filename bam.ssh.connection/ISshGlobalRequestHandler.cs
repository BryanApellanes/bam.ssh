namespace Bam.Ssh.Connection;

/// <summary>
/// Decides what to do with a peer-initiated SSH_MSG_GLOBAL_REQUEST (RFC 4254 §4) whose name is registered
/// on an <see cref="SshConnection"/> via <see cref="SshConnection.RegisterGlobalRequestHandler"/> — for
/// example a server handling <c>tcpip-forward</c>. The handler runs on the connection's dispatch loop, so
/// it must not block: resolve the request (accept or reject) and hand any real work — binding a listener,
/// running an accept loop — to a separate task, otherwise the connection stalls. When the handler leaves
/// the request unresolved, the connection replies SSH_MSG_REQUEST_FAILURE if a reply was wanted.
/// </summary>
public interface ISshGlobalRequestHandler
{
    /// <summary>
    /// Handles a registered inbound global request by calling <see cref="SshGlobalRequestContext.Accept"/>
    /// or <see cref="SshGlobalRequestContext.Reject"/> on the context.
    /// </summary>
    /// <param name="context">The inbound request and the accept/reject controls.</param>
    /// <param name="cancellationToken">Cancels the handling.</param>
    ValueTask HandleRequestAsync(SshGlobalRequestContext context, CancellationToken cancellationToken);
}
