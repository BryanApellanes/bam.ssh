using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Bam.Ssh.Client;

/// <summary>
/// An <see cref="ISshHostKeyVerifier"/> backed by an OpenSSH <c>known_hosts</c> file. It matches the host
/// against each entry — plain host patterns and <c>[host]:port</c> forms, plus HMAC-SHA1 hashed entries
/// (<c>|1|salt|hash</c>) — and compares the stored key blob to the server's. A byte-identical stored key
/// is trusted; a stored key of the same type that <em>differs</em> is rejected as a possible
/// man-in-the-middle; a host with no stored key is accepted and appended in <see cref="SshKnownHostsMode.Tofu"/>
/// mode or rejected in <see cref="SshKnownHostsMode.Strict"/> mode.
/// </summary>
/// <remarks>
/// Hashed-host matching uses HMAC-SHA1 because that is the exact construction OpenSSH's
/// <c>HashKnownHosts</c> uses; SHA-1 here is an interoperability requirement, not a security primitive
/// (the hash only obscures which hosts you have connected to). All other hashing in the stack is SHA-2.
/// </remarks>
public sealed class KnownHostsHostKeyVerifier : ISshHostKeyVerifier
{
    private readonly string _path;
    private readonly SshKnownHostsMode _mode;
    private readonly object _fileLock = new object();

    /// <summary>
    /// Initializes the verifier over a known_hosts file.
    /// </summary>
    /// <param name="path">The known_hosts file path (need not exist yet in TOFU mode).</param>
    /// <param name="mode">How to treat a first-seen host key.</param>
    /// <exception cref="ArgumentException">The path is null or empty.</exception>
    public KnownHostsHostKeyVerifier(string path, SshKnownHostsMode mode = SshKnownHostsMode.Tofu)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        _path = path;
        _mode = mode;
    }

    /// <summary>
    /// Creates a strict verifier over the given known_hosts file (first-seen keys are rejected).
    /// </summary>
    /// <param name="path">The known_hosts file path.</param>
    /// <returns>A strict verifier.</returns>
    public static KnownHostsHostKeyVerifier Strict(string path) => new KnownHostsHostKeyVerifier(path, SshKnownHostsMode.Strict);

    /// <summary>
    /// Creates a trust-on-first-use verifier over the given known_hosts file.
    /// </summary>
    /// <param name="path">The known_hosts file path.</param>
    /// <returns>A TOFU verifier.</returns>
    public static KnownHostsHostKeyVerifier Tofu(string path) => new KnownHostsHostKeyVerifier(path, SshKnownHostsMode.Tofu);

    /// <summary>
    /// Returns the path to the current user's default known_hosts file (<c>~/.ssh/known_hosts</c>).
    /// </summary>
    /// <returns>The default known_hosts path.</returns>
    public static string DefaultPath()
    {
        string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return Path.Combine(home, ".ssh", "known_hosts");
    }

    /// <inheritdoc/>
    public ValueTask<bool> VerifyAsync(SshHostKeyVerificationContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        string hostToken = FormatHost(context.Host, context.Port);
        string keyType = context.HostKey.Algorithm;
        string keyBase64 = Convert.ToBase64String(context.HostKey.KeyBlob.Span);

        lock (_fileLock)
        {
            HostKeyMatch match = FindMatch(hostToken, keyType, keyBase64);
            switch (match)
            {
                case HostKeyMatch.Trusted:
                    return ValueTask.FromResult(true);
                case HostKeyMatch.Changed:
                    // A stored key of the same type differs — refuse, never silently overwrite.
                    return ValueTask.FromResult(false);
                default:
                    if (_mode == SshKnownHostsMode.Strict)
                    {
                        return ValueTask.FromResult(false);
                    }
                    Append(hostToken, keyType, keyBase64);
                    return ValueTask.FromResult(true);
            }
        }
    }

    private HostKeyMatch FindMatch(string hostToken, string keyType, string keyBase64)
    {
        if (!File.Exists(_path))
        {
            return HostKeyMatch.Unknown;
        }

        bool sawHostWithSameType = false;
        foreach (string rawLine in File.ReadLines(_path))
        {
            string line = rawLine.Trim();
            if (line.Length == 0 || line[0] == '#')
            {
                continue;
            }

            string[] fields = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length < 3)
            {
                continue;
            }
            int index = 0;
            if (fields[0].StartsWith('@'))
            {
                // Skip markers such as @revoked / @cert-authority (unsupported this phase).
                index = 1;
                if (fields.Length < 4)
                {
                    continue;
                }
            }

            string hostField = fields[index];
            string typeField = fields[index + 1];
            string keyField = fields[index + 2];
            if (!HostMatches(hostField, hostToken))
            {
                continue;
            }
            if (!string.Equals(typeField, keyType, StringComparison.Ordinal))
            {
                continue;
            }
            sawHostWithSameType = true;
            if (string.Equals(keyField, keyBase64, StringComparison.Ordinal))
            {
                return HostKeyMatch.Trusted;
            }
        }

        return sawHostWithSameType ? HostKeyMatch.Changed : HostKeyMatch.Unknown;
    }

    private static bool HostMatches(string hostField, string hostToken)
    {
        foreach (string pattern in hostField.Split(',', StringSplitOptions.RemoveEmptyEntries))
        {
            if (pattern.StartsWith("|1|", StringComparison.Ordinal))
            {
                if (HashedHostMatches(pattern, hostToken))
                {
                    return true;
                }
            }
            else if (string.Equals(pattern, hostToken, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    private static bool HashedHostMatches(string pattern, string hostToken)
    {
        string[] parts = pattern.Split('|');
        // parts: ["", "1", saltBase64, hashBase64]
        if (parts.Length != 4)
        {
            return false;
        }
        try
        {
            byte[] salt = Convert.FromBase64String(parts[2]);
            byte[] expected = Convert.FromBase64String(parts[3]);
            byte[] actual = HMACSHA1.HashData(salt, Encoding.ASCII.GetBytes(hostToken));
            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private void Append(string hostToken, string keyType, string keyBase64)
    {
        string? directory = Path.GetDirectoryName(_path);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }
        string line = string.Create(CultureInfo.InvariantCulture, $"{hostToken} {keyType} {keyBase64}\n");
        File.AppendAllText(_path, line);
    }

    private static string FormatHost(string host, int port)
    {
        return port == 22 ? host : string.Create(CultureInfo.InvariantCulture, $"[{host}]:{port}");
    }

    private enum HostKeyMatch
    {
        Unknown,
        Trusted,
        Changed,
    }
}
