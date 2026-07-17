namespace Bam.Ssh.Scp;

/// <summary>
/// The role a parsed <c>scp</c> command line asks the invoked peer to play.
/// </summary>
public enum ScpTransferMode
{
    /// <summary>Sink mode (<c>scp -t</c>): the peer receives files the initiator sends.</summary>
    Sink,

    /// <summary>Source mode (<c>scp -f</c>): the peer sends files the initiator receives.</summary>
    Source,
}
