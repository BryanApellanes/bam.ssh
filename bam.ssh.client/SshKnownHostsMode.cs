namespace Bam.Ssh.Client;

/// <summary>
/// How a <see cref="KnownHostsHostKeyVerifier"/> treats a host key it has never seen before.
/// </summary>
public enum SshKnownHostsMode
{
    /// <summary>
    /// Trust-on-first-use: a first-seen key is accepted and appended to the known_hosts file. A key that
    /// <em>differs</em> from a previously stored one for the host is always rejected.
    /// </summary>
    Tofu,

    /// <summary>
    /// Strict: only keys already present in the known_hosts file are accepted; a first-seen key is rejected.
    /// </summary>
    Strict,
}
