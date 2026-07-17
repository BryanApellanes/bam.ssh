using System.Globalization;

namespace Bam.Ssh.Scp;

/// <summary>
/// One parsed SCP control record — the newline-terminated line a source sends before file data or a
/// directory: <c>C&lt;mode&gt; &lt;size&gt; &lt;name&gt;</c>, <c>D&lt;mode&gt; 0 &lt;name&gt;</c>, <c>E</c>,
/// or <c>T&lt;mtime&gt; 0 &lt;atime&gt; 0</c>. Parsing is synchronous and total (any malformed input throws
/// <see cref="ScpException"/>), and the static formatters produce the matching wire strings.
/// </summary>
public sealed class ScpControlMessage
{
    private ScpControlMessage(ScpControlType type, uint mode, long size, string name, long modifyTime, long accessTime)
    {
        Type = type;
        Mode = mode;
        Size = size;
        Name = name;
        ModifyTime = modifyTime;
        AccessTime = accessTime;
    }

    /// <summary>Gets the record kind.</summary>
    public ScpControlType Type { get; }

    /// <summary>Gets the POSIX permission bits for a <see cref="ScpControlType.File"/> or <see cref="ScpControlType.Directory"/> record.</summary>
    public uint Mode { get; }

    /// <summary>Gets the file length for a <see cref="ScpControlType.File"/> record; zero otherwise.</summary>
    public long Size { get; }

    /// <summary>Gets the entry name for a <see cref="ScpControlType.File"/> or <see cref="ScpControlType.Directory"/> record; empty otherwise.</summary>
    public string Name { get; }

    /// <summary>Gets the modification time (Unix seconds) for a <see cref="ScpControlType.Time"/> record; zero otherwise.</summary>
    public long ModifyTime { get; }

    /// <summary>Gets the access time (Unix seconds) for a <see cref="ScpControlType.Time"/> record; zero otherwise.</summary>
    public long AccessTime { get; }

    /// <summary>
    /// Parses a control line (without its trailing newline).
    /// </summary>
    /// <param name="line">The control line.</param>
    /// <returns>The parsed record.</returns>
    /// <exception cref="ArgumentNullException">The line is null.</exception>
    /// <exception cref="ScpException">The line is empty or malformed.</exception>
    public static ScpControlMessage Parse(string line)
    {
        ArgumentNullException.ThrowIfNull(line);
        if (line.Length == 0)
        {
            throw new ScpException("Received an empty SCP control record.");
        }

        char kind = line[0];
        switch (kind)
        {
            case 'C':
                return ParseFileOrDirectory(ScpControlType.File, line);
            case 'D':
                return ParseFileOrDirectory(ScpControlType.Directory, line);
            case 'E':
                return new ScpControlMessage(ScpControlType.EndDirectory, 0, 0, string.Empty, 0, 0);
            case 'T':
                return ParseTime(line);
            default:
                throw new ScpException($"Unrecognized SCP control record '{kind}'.");
        }
    }

    /// <summary>
    /// Formats a <c>C</c> file record line (without the trailing newline).
    /// </summary>
    /// <param name="mode">The permission bits (only the low twelve are used).</param>
    /// <param name="size">The file length in bytes.</param>
    /// <param name="name">The single-component file name.</param>
    /// <returns>The wire line.</returns>
    public static string FormatFile(uint mode, long size, string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        return string.Concat("C", FormatMode(mode), " ", size.ToString(CultureInfo.InvariantCulture), " ", name);
    }

    /// <summary>
    /// Formats a <c>D</c> directory-start record line (without the trailing newline). The size field is always zero.
    /// </summary>
    /// <param name="mode">The permission bits (only the low twelve are used).</param>
    /// <param name="name">The single-component directory name.</param>
    /// <returns>The wire line.</returns>
    public static string FormatDirectory(uint mode, string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        return string.Concat("D", FormatMode(mode), " 0 ", name);
    }

    /// <summary>
    /// Formats a <c>T</c> timestamps record line (without the trailing newline). Sub-second fields are always zero.
    /// </summary>
    /// <param name="modifyTime">The modification time in Unix seconds.</param>
    /// <param name="accessTime">The access time in Unix seconds.</param>
    /// <returns>The wire line.</returns>
    public static string FormatTime(long modifyTime, long accessTime)
    {
        return string.Concat(
            "T",
            modifyTime.ToString(CultureInfo.InvariantCulture),
            " 0 ",
            accessTime.ToString(CultureInfo.InvariantCulture),
            " 0");
    }

    /// <summary>The <c>E</c> directory-end record line (without the trailing newline).</summary>
    public const string EndDirectoryLine = "E";

    private static ScpControlMessage ParseFileOrDirectory(ScpControlType type, string line)
    {
        // Layout: <kind><octal-mode> <decimal-size> <name...>. The name is the remainder and may contain spaces.
        int firstSpace = line.IndexOf(' ', StringComparison.Ordinal);
        if (firstSpace < 0)
        {
            throw new ScpException($"Malformed SCP control record: '{line}'.");
        }

        int secondSpace = line.IndexOf(' ', firstSpace + 1);
        if (secondSpace < 0)
        {
            throw new ScpException($"Malformed SCP control record: '{line}'.");
        }

        string modeText = line.Substring(1, firstSpace - 1);
        string sizeText = line.Substring(firstSpace + 1, secondSpace - firstSpace - 1);
        string name = line.Substring(secondSpace + 1);

        uint mode = ParseOctal(modeText, line);
        if (!long.TryParse(sizeText, NumberStyles.None, CultureInfo.InvariantCulture, out long size))
        {
            throw new ScpException($"Malformed size in SCP control record: '{line}'.");
        }

        if (name.Length == 0)
        {
            throw new ScpException($"Missing name in SCP control record: '{line}'.");
        }

        return new ScpControlMessage(type, mode, size, name, 0, 0);
    }

    private static ScpControlMessage ParseTime(string line)
    {
        // Layout: T<mtime> <mtime_usec> <atime> <atime_usec>.
        string[] parts = line.Substring(1).Split(' ');
        if (parts.Length != 4)
        {
            throw new ScpException($"Malformed SCP time record: '{line}'.");
        }

        if (!long.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out long modifyTime) ||
            !long.TryParse(parts[2], NumberStyles.None, CultureInfo.InvariantCulture, out long accessTime))
        {
            throw new ScpException($"Malformed SCP time record: '{line}'.");
        }

        return new ScpControlMessage(ScpControlType.Time, 0, 0, string.Empty, modifyTime, accessTime);
    }

    private static uint ParseOctal(string text, string line)
    {
        if (text.Length == 0)
        {
            throw new ScpException($"Missing mode in SCP control record: '{line}'.");
        }

        uint value = 0;
        foreach (char c in text)
        {
            if (c < '0' || c > '7')
            {
                throw new ScpException($"Malformed octal mode in SCP control record: '{line}'.");
            }

            value = (value << 3) + (uint)(c - '0');
        }

        return value;
    }

    private static string FormatMode(uint mode)
    {
        // Four octal digits of the permission bits, matching OpenSSH's "%04o".
        uint bits = mode & 0xFFF;
        Span<char> digits = stackalloc char[4];
        for (int i = 3; i >= 0; i--)
        {
            digits[i] = (char)('0' + (int)(bits & 0x7));
            bits >>= 3;
        }

        return new string(digits);
    }
}
