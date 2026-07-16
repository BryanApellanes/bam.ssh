namespace Bam.Ssh.Authentication;

/// <summary>
/// The category of an authentication reply an <see cref="ISshAuthenticationMethod"/> observes.
/// </summary>
public enum SshAuthenticationReplyKind
{
    /// <summary>SSH_MSG_USERAUTH_SUCCESS — authentication completed; the connection protocol may start.</summary>
    Success,

    /// <summary>SSH_MSG_USERAUTH_FAILURE — the attempt was rejected; another method may continue.</summary>
    Failure,

    /// <summary>A method-specific message (60–79) the running method must interpret.</summary>
    MethodSpecific
}

/// <summary>
/// A classified reply to an authentication request. The orchestrator handles the generic messages
/// (SUCCESS/FAILURE, and transparently BANNER) and hands method-specific messages (60–79) to the
/// running method through this discriminated type. <see cref="Kind"/> selects which fields are valid.
/// </summary>
public sealed class SshAuthenticationReply
{
    private SshAuthenticationReply(
        SshAuthenticationReplyKind kind,
        SshNameList methodsThatCanContinue,
        bool partialSuccess,
        byte messageNumber,
        ReadOnlyMemory<byte> body)
    {
        Kind = kind;
        MethodsThatCanContinue = methodsThatCanContinue;
        PartialSuccess = partialSuccess;
        MessageNumber = messageNumber;
        Body = body;
    }

    /// <summary>Gets the reply category.</summary>
    public SshAuthenticationReplyKind Kind { get; }

    /// <summary>
    /// Gets the authentications that can continue, when <see cref="Kind"/> is
    /// <see cref="SshAuthenticationReplyKind.Failure"/>; otherwise empty.
    /// </summary>
    public SshNameList MethodsThatCanContinue { get; }

    /// <summary>
    /// Gets whether the failure reported partial success (a prior method in a multi-step sequence
    /// succeeded), when <see cref="Kind"/> is <see cref="SshAuthenticationReplyKind.Failure"/>.
    /// </summary>
    public bool PartialSuccess { get; }

    /// <summary>
    /// Gets the message number, when <see cref="Kind"/> is
    /// <see cref="SshAuthenticationReplyKind.MethodSpecific"/>.
    /// </summary>
    public byte MessageNumber { get; }

    /// <summary>
    /// Gets the message body after the message-number byte, when <see cref="Kind"/> is
    /// <see cref="SshAuthenticationReplyKind.MethodSpecific"/>.
    /// </summary>
    public ReadOnlyMemory<byte> Body { get; }

    /// <summary>Creates a success reply.</summary>
    /// <returns>A success reply.</returns>
    public static SshAuthenticationReply CreateSuccess()
    {
        return new SshAuthenticationReply(SshAuthenticationReplyKind.Success, SshNameList.Empty, false, 0, ReadOnlyMemory<byte>.Empty);
    }

    /// <summary>Creates a failure reply.</summary>
    /// <param name="methodsThatCanContinue">The authentications that can continue.</param>
    /// <param name="partialSuccess">Whether partial success was reported.</param>
    /// <returns>A failure reply.</returns>
    public static SshAuthenticationReply CreateFailure(SshNameList methodsThatCanContinue, bool partialSuccess)
    {
        return new SshAuthenticationReply(SshAuthenticationReplyKind.Failure, methodsThatCanContinue, partialSuccess, 0, ReadOnlyMemory<byte>.Empty);
    }

    /// <summary>Creates a method-specific reply.</summary>
    /// <param name="messageNumber">The message number (60–79).</param>
    /// <param name="body">The message body after the message-number byte.</param>
    /// <returns>A method-specific reply.</returns>
    public static SshAuthenticationReply CreateMethodSpecific(byte messageNumber, ReadOnlyMemory<byte> body)
    {
        return new SshAuthenticationReply(SshAuthenticationReplyKind.MethodSpecific, SshNameList.Empty, false, messageNumber, body);
    }
}
