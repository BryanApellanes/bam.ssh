using System.Text;

namespace Bam.Ssh.Sftp;

/// <summary>
/// Formats the human-readable "long name" an SFTP <see cref="SftpPacketType.Name"/> entry carries — an
/// <c>ls -l</c>-style line. It is presentational only (clients parse the structured attributes, not this
/// string), so the format is a faithful-looking approximation, not a parsed contract.
/// </summary>
public static class SftpLongName
{
    /// <summary>
    /// Formats an <c>ls -l</c>-style line for a name and its attributes.
    /// </summary>
    /// <param name="fileName">The entry's file name.</param>
    /// <param name="attributes">The entry's attributes.</param>
    /// <returns>The formatted line.</returns>
    public static string Format(string fileName, SftpFileAttributes attributes)
    {
        ArgumentNullException.ThrowIfNull(fileName);
        ArgumentNullException.ThrowIfNull(attributes);
        uint mode = attributes.Permissions ?? SftpConstants.ModeRegularFile;
        ulong size = attributes.Size ?? 0;
        StringBuilder builder = new StringBuilder();
        builder.Append(FormatMode(mode));
        builder.Append(" 1 owner group ");
        builder.Append(size.ToString().PadLeft(12));
        builder.Append(" Jan  1 00:00 ");
        builder.Append(fileName);
        return builder.ToString();
    }

    private static string FormatMode(uint mode)
    {
        char type = (mode & SftpConstants.ModeFormatMask) switch
        {
            SftpConstants.ModeDirectory => 'd',
            SftpConstants.ModeSymbolicLink => 'l',
            _ => '-',
        };
        Span<char> bits = stackalloc char[9];
        const string rwx = "rwxrwxrwx";
        for (int i = 0; i < 9; i++)
        {
            bool set = (mode & (1u << (8 - i))) != 0;
            bits[i] = set ? rwx[i] : '-';
        }
        return string.Concat(type.ToString(), new string(bits));
    }
}
