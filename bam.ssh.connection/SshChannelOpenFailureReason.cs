namespace Bam.Ssh.Connection;

/// <summary>
/// The reason codes a peer may return in an SSH_MSG_CHANNEL_OPEN_FAILURE message (RFC 4254 §5.1).
/// </summary>
public enum SshChannelOpenFailureReason : uint
{
    /// <summary>
    /// The administrator's policy forbids the requested channel (SSH_OPEN_ADMINISTRATIVELY_PROHIBITED).
    /// </summary>
    AdministrativelyProhibited = 1,

    /// <summary>
    /// The channel could not be opened because a required connection failed (SSH_OPEN_CONNECT_FAILED).
    /// </summary>
    ConnectFailed = 2,

    /// <summary>
    /// The requested channel type is not recognized (SSH_OPEN_UNKNOWN_CHANNEL_TYPE).
    /// </summary>
    UnknownChannelType = 3,

    /// <summary>
    /// The peer is temporarily out of resources to open the channel (SSH_OPEN_RESOURCE_SHORTAGE).
    /// </summary>
    ResourceShortage = 4,
}
