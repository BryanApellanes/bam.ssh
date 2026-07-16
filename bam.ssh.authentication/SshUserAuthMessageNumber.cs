namespace Bam.Ssh.Authentication;

/// <summary>
/// The method-specific user-authentication message numbers (RFC 4252 §6, RFC 4256 §3.2). These
/// occupy the 60–79 range whose meaning depends on the authentication method currently in progress —
/// the same number 60 is <c>SSH_MSG_USERAUTH_PK_OK</c> for publickey but
/// <c>SSH_MSG_USERAUTH_PASSWD_CHANGEREQ</c> for password and <c>SSH_MSG_USERAUTH_INFO_REQUEST</c> for
/// keyboard-interactive. Because the numbers overlap, they are kept here (interpreted by the running
/// method) rather than in the shared <see cref="SshMessageNumber"/> enum, whose values must be
/// globally unambiguous.
/// </summary>
public static class SshUserAuthMessageNumber
{
    /// <summary>SSH_MSG_USERAUTH_PK_OK (60, publickey) — the offered public key is acceptable; sign and resend.</summary>
    public const byte PublicKeyOk = 60;

    /// <summary>SSH_MSG_USERAUTH_PASSWD_CHANGEREQ (60, password) — the password must be changed before login.</summary>
    public const byte PasswordChangeRequest = 60;

    /// <summary>SSH_MSG_USERAUTH_INFO_REQUEST (60, keyboard-interactive) — a set of prompts to answer.</summary>
    public const byte InformationRequest = 60;

    /// <summary>SSH_MSG_USERAUTH_INFO_RESPONSE (61, keyboard-interactive) — the answers to the prompts.</summary>
    public const byte InformationResponse = 61;
}
