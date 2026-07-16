namespace Bam.Ssh.Authentication;

/// <summary>
/// The canonical service and method name strings used by the authentication protocol (RFC 4252,
/// RFC 4256), centralized so the orchestrator, methods, and tests share one spelling.
/// </summary>
public static class SshAuthenticationNames
{
    /// <summary>The service requested to begin user authentication (RFC 4252 §5).</summary>
    public const string UserAuthService = "ssh-userauth";

    /// <summary>The service authenticated for — the connection protocol (RFC 4252 §5, RFC 4254).</summary>
    public const string ConnectionService = "ssh-connection";

    /// <summary>The <c>none</c> method (RFC 4252 §5.2) — a probe that surfaces the acceptable methods.</summary>
    public const string None = "none";

    /// <summary>The <c>password</c> method (RFC 4252 §8).</summary>
    public const string Password = "password";

    /// <summary>The <c>publickey</c> method (RFC 4252 §7).</summary>
    public const string PublicKey = "publickey";

    /// <summary>The <c>keyboard-interactive</c> method (RFC 4256).</summary>
    public const string KeyboardInteractive = "keyboard-interactive";
}
