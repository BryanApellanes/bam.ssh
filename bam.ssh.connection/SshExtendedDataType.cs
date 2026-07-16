namespace Bam.Ssh.Connection;

/// <summary>
/// The data-type codes carried by SSH_MSG_CHANNEL_EXTENDED_DATA (RFC 4254 §5.2). Only standard error
/// is defined by the base protocol.
/// </summary>
public enum SshExtendedDataType : uint
{
    /// <summary>
    /// The extended data is the channel's standard error stream (SSH_EXTENDED_DATA_STDERR).
    /// </summary>
    StandardError = 1,
}
