namespace Bam.Ssh.Forwarding;

/// <summary>
/// A policy predicate a server uses to permit or deny a peer's request to connect to a target host and port
/// (the connect side of local/dynamic forwarding). Returns true to allow the connection.
/// </summary>
/// <param name="host">The target host the peer asked to reach.</param>
/// <param name="port">The target port.</param>
public delegate bool SshForwardingTargetFilter(string host, int port);

/// <summary>
/// A policy predicate a server uses to permit or deny a peer's request to bind and listen on an address and
/// port (the listen side of remote forwarding). Returns true to allow the bind.
/// </summary>
/// <param name="bindAddress">The address the peer asked the server to bind.</param>
/// <param name="bindPort">The port the peer asked the server to bind (0 to let the server choose).</param>
public delegate bool SshForwardingBindFilter(string bindAddress, int bindPort);
