namespace Bam.Ssh.Sftp;

/// <summary>
/// One entry in an SFTP <see cref="SftpPacketType.Name"/> response: the file name, the human-readable long
/// name (an <c>ls -l</c>-style line the server formats), and the file's attributes. Directory listings and
/// canonicalized paths are returned as sequences of these.
/// </summary>
public sealed class SftpName
{
    /// <summary>
    /// Initializes a name entry.
    /// </summary>
    /// <param name="fileName">The file name (a single path component for a listing).</param>
    /// <param name="longName">The human-readable listing line.</param>
    /// <param name="attributes">The file's attributes.</param>
    /// <exception cref="ArgumentNullException">Any argument is null.</exception>
    public SftpName(string fileName, string longName, SftpFileAttributes attributes)
    {
        ArgumentNullException.ThrowIfNull(fileName);
        ArgumentNullException.ThrowIfNull(longName);
        ArgumentNullException.ThrowIfNull(attributes);
        FileName = fileName;
        LongName = longName;
        Attributes = attributes;
    }

    /// <summary>Gets the file name.</summary>
    public string FileName { get; }

    /// <summary>Gets the human-readable listing line.</summary>
    public string LongName { get; }

    /// <summary>Gets the file's attributes.</summary>
    public SftpFileAttributes Attributes { get; }
}
