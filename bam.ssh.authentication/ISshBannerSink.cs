namespace Bam.Ssh.Authentication;

/// <summary>
/// Receives SSH_MSG_USERAUTH_BANNER text (RFC 4252 §5.4) that a server may send before authentication
/// completes — typically a legal notice or message of the day meant to be shown to the user. The
/// orchestrator surfaces banners here and continues reading the next reply.
/// </summary>
public interface ISshBannerSink
{
    /// <summary>
    /// Called when a banner is received.
    /// </summary>
    /// <param name="message">The banner text.</param>
    /// <param name="languageTag">The RFC 3066 language tag (often empty).</param>
    void OnBanner(string message, string languageTag);
}

/// <summary>
/// An <see cref="ISshBannerSink"/> that discards banners. Used when the caller supplies no sink.
/// </summary>
public sealed class NullSshBannerSink : ISshBannerSink
{
    /// <summary>Gets the shared instance.</summary>
    public static NullSshBannerSink Instance { get; } = new NullSshBannerSink();

    private NullSshBannerSink()
    {
    }

    /// <inheritdoc/>
    public void OnBanner(string message, string languageTag)
    {
    }
}
