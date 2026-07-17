using System.Text;

namespace Bam.Ssh.Sftp;

/// <summary>
/// Helpers for the SFTP path namespace: paths are always '/'-separated and canonicalized to an absolute
/// form with <c>.</c> and <c>..</c> resolved, independent of the host OS path rules. Used by the virtual
/// filesystems to normalize wire paths before mapping them to a backing store.
/// </summary>
public static class SftpPath
{
    /// <summary>The canonical root path.</summary>
    public const string Root = "/";

    /// <summary>
    /// Canonicalizes a path to an absolute '/'-separated form, resolving empty segments, <c>.</c>, and
    /// <c>..</c>. A relative path is taken relative to the root, so <c>.</c> canonicalizes to <c>/</c>.
    /// </summary>
    /// <param name="path">The path to canonicalize.</param>
    /// <returns>The canonical absolute path (never empty; the root is <c>/</c>).</returns>
    /// <exception cref="ArgumentNullException">The path is null.</exception>
    public static string Canonicalize(string path)
    {
        ArgumentNullException.ThrowIfNull(path);
        List<string> segments = new List<string>();
        foreach (string raw in path.Split('/'))
        {
            if (raw.Length == 0 || raw == ".")
            {
                continue;
            }
            if (raw == "..")
            {
                if (segments.Count > 0)
                {
                    segments.RemoveAt(segments.Count - 1);
                }
                continue;
            }
            segments.Add(raw);
        }
        if (segments.Count == 0)
        {
            return Root;
        }
        StringBuilder builder = new StringBuilder();
        foreach (string segment in segments)
        {
            builder.Append('/').Append(segment);
        }
        return builder.ToString();
    }

    /// <summary>
    /// Splits a canonical path into its segments (the root yields an empty array).
    /// </summary>
    /// <param name="path">The path.</param>
    /// <returns>The path segments.</returns>
    public static string[] Split(string path)
    {
        string canonical = Canonicalize(path);
        if (canonical == Root)
        {
            return Array.Empty<string>();
        }
        return canonical.Substring(1).Split('/');
    }

    /// <summary>
    /// Gets the last segment (file or directory name) of a canonical path, or the empty string for the root.
    /// </summary>
    /// <param name="path">The path.</param>
    /// <returns>The final segment.</returns>
    public static string GetFileName(string path)
    {
        string[] segments = Split(path);
        return segments.Length == 0 ? string.Empty : segments[^1];
    }

    /// <summary>
    /// Gets the canonical parent path of a path (the root's parent is the root).
    /// </summary>
    /// <param name="path">The path.</param>
    /// <returns>The parent path.</returns>
    public static string GetParent(string path)
    {
        string[] segments = Split(path);
        if (segments.Length <= 1)
        {
            return Root;
        }
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < segments.Length - 1; i++)
        {
            builder.Append('/').Append(segments[i]);
        }
        return builder.ToString();
    }
}
