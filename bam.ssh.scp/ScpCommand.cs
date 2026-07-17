using System.Collections.Generic;
using System.Text;

namespace Bam.Ssh.Scp;

/// <summary>
/// A parsed remote <c>scp</c> command line — the string a peer runs via <c>exec</c> to enter the SCP binary
/// protocol (for example <c>scp -t -r /var/data</c> or <c>scp -f "/home/me/file name.txt"</c>). Carries the
/// requested <see cref="ScpTransferMode"/>, the recursive and preserve-times flags, and the target path.
/// Used by the server's <c>MapScp</c> handler to decide which role engine to run.
/// </summary>
public sealed class ScpCommand
{
    private ScpCommand(ScpTransferMode mode, bool recursive, bool preserveTimes, string path)
    {
        Mode = mode;
        Recursive = recursive;
        PreserveTimes = preserveTimes;
        Path = path;
    }

    /// <summary>Gets the requested transfer role.</summary>
    public ScpTransferMode Mode { get; }

    /// <summary>Gets whether the <c>-r</c> (recursive) flag was present.</summary>
    public bool Recursive { get; }

    /// <summary>Gets whether the <c>-p</c> (preserve modification/access times) flag was present.</summary>
    public bool PreserveTimes { get; }

    /// <summary>Gets the target path (the command line's final argument).</summary>
    public string Path { get; }

    /// <summary>
    /// Determines whether a command line is an SCP invocation this stack services.
    /// </summary>
    /// <param name="commandLine">The exec command line.</param>
    /// <returns>True if the first token is <c>scp</c> (optionally path-qualified).</returns>
    public static bool IsScpCommand(string commandLine)
    {
        if (string.IsNullOrEmpty(commandLine))
        {
            return false;
        }

        IReadOnlyList<string> tokens = Tokenize(commandLine);
        return tokens.Count > 0 && IsScpProgram(tokens[0]);
    }

    /// <summary>
    /// Parses an <c>scp</c> command line.
    /// </summary>
    /// <param name="commandLine">The exec command line.</param>
    /// <returns>The parsed command.</returns>
    /// <exception cref="ArgumentNullException">The command line is null.</exception>
    /// <exception cref="ScpException">The line is not an <c>scp</c> invocation, lacks a mode flag, or lacks a path.</exception>
    public static ScpCommand Parse(string commandLine)
    {
        ArgumentNullException.ThrowIfNull(commandLine);
        IReadOnlyList<string> tokens = Tokenize(commandLine);
        if (tokens.Count == 0 || !IsScpProgram(tokens[0]))
        {
            throw new ScpException($"Not an scp command: '{commandLine}'.");
        }

        bool sink = false;
        bool source = false;
        bool recursive = false;
        bool preserveTimes = false;
        string? path = null;

        for (int i = 1; i < tokens.Count; i++)
        {
            string token = tokens[i];
            if (token.Length >= 2 && token[0] == '-')
            {
                // Flags may be bundled (e.g. -rt); each letter is handled independently.
                foreach (char flag in token.AsSpan(1))
                {
                    switch (flag)
                    {
                        case 't':
                            sink = true;
                            break;
                        case 'f':
                            source = true;
                            break;
                        case 'r':
                            recursive = true;
                            break;
                        case 'p':
                            preserveTimes = true;
                            break;
                        // -d (target must be a directory), -v (verbose), -q (quiet), -B, -C are accepted and ignored.
                        case 'd':
                        case 'v':
                        case 'q':
                        case 'B':
                        case 'C':
                        case 'E':
                            break;
                        default:
                            throw new ScpException($"Unsupported scp flag '-{flag}' in '{commandLine}'.");
                    }
                }
            }
            else
            {
                // The last non-flag token is the target path.
                path = token;
            }
        }

        if (sink == source)
        {
            throw new ScpException($"scp command must specify exactly one of -t or -f: '{commandLine}'.");
        }

        if (string.IsNullOrEmpty(path))
        {
            throw new ScpException($"scp command is missing a path: '{commandLine}'.");
        }

        return new ScpCommand(sink ? ScpTransferMode.Sink : ScpTransferMode.Source, recursive, preserveTimes, path);
    }

    private static bool IsScpProgram(string token)
    {
        // Accept "scp", "/usr/bin/scp", "scp.exe", etc.
        int lastSlash = token.LastIndexOfAny(new[] { '/', '\\' });
        string program = lastSlash >= 0 ? token.Substring(lastSlash + 1) : token;
        if (program.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            program = program.Substring(0, program.Length - 4);
        }

        return string.Equals(program, "scp", StringComparison.Ordinal);
    }

    private static IReadOnlyList<string> Tokenize(string commandLine)
    {
        // A minimal shell-style tokenizer: splits on unquoted whitespace, honoring single and double quotes
        // and a backslash escape, which is enough for the paths scp passes over exec.
        List<string> tokens = new List<string>();
        StringBuilder current = new StringBuilder();
        bool inToken = false;
        char quote = '\0';

        for (int i = 0; i < commandLine.Length; i++)
        {
            char c = commandLine[i];
            if (quote != '\0')
            {
                if (c == quote)
                {
                    quote = '\0';
                }
                else
                {
                    current.Append(c);
                }

                continue;
            }

            switch (c)
            {
                case '\'':
                case '"':
                    quote = c;
                    inToken = true;
                    break;
                case '\\':
                    if (i + 1 < commandLine.Length)
                    {
                        current.Append(commandLine[++i]);
                        inToken = true;
                    }

                    break;
                case ' ':
                case '\t':
                    if (inToken)
                    {
                        tokens.Add(current.ToString());
                        current.Clear();
                        inToken = false;
                    }

                    break;
                default:
                    current.Append(c);
                    inToken = true;
                    break;
            }
        }

        if (inToken)
        {
            tokens.Add(current.ToString());
        }

        return tokens;
    }
}
