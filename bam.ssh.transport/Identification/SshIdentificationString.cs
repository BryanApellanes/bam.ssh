using System.Text;

namespace Bam.Ssh.Transport;

/// <summary>
/// The RFC 4253 §4.2 identification string exchanged before the binary packet protocol begins:
/// <c>SSH-protoversion-softwareversion SP comments</c> (the trailing comments and its space are
/// optional). The line is US-ASCII, must not contain NUL, CR, or LF, and — excluding the CRLF —
/// must not exceed 255 bytes. This value type parses and formats that line; the transport keeps
/// the raw bytes separately for the key-exchange hash.
/// </summary>
public readonly struct SshIdentificationString
{
    /// <summary>
    /// The protocol version bam.ssh implements and advertises.
    /// </summary>
    public const string SupportedProtocolVersion = "2.0";

    /// <summary>
    /// Initializes an identification string from its parts.
    /// </summary>
    /// <param name="protocolVersion">The protocol version (e.g. <c>2.0</c>).</param>
    /// <param name="softwareVersion">The software version; must be non-empty printable ASCII with no space or minus.</param>
    /// <param name="comments">Optional comments; may be null or empty.</param>
    /// <exception cref="ArgumentException">A part violates the RFC 4253 §4.2 character rules.</exception>
    public SshIdentificationString(string protocolVersion, string softwareVersion, string? comments = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(protocolVersion);
        ArgumentException.ThrowIfNullOrEmpty(softwareVersion);
        ValidateSoftwareVersion(softwareVersion);
        if (comments is not null)
        {
            ValidatePrintableAscii(comments, nameof(comments));
        }
        ProtocolVersion = protocolVersion;
        SoftwareVersion = softwareVersion;
        Comments = comments;
    }

    /// <summary>
    /// Gets the protocol version (the field between the first two hyphens, e.g. <c>2.0</c>).
    /// </summary>
    public string ProtocolVersion { get; }

    /// <summary>
    /// Gets the software version (the implementation identifier, e.g. <c>Bam.Ssh_1.0</c>).
    /// </summary>
    public string SoftwareVersion { get; }

    /// <summary>
    /// Gets the optional comments, or null when none were supplied.
    /// </summary>
    public string? Comments { get; }

    /// <summary>
    /// Gets whether this identification advertises a protocol version bam.ssh can speak
    /// (<c>2.0</c>, or <c>1.99</c> which per RFC 4253 §5.1 means a 1.x server that also speaks 2.0).
    /// </summary>
    public bool IsProtocolSupported =>
        ProtocolVersion == SupportedProtocolVersion || ProtocolVersion == "1.99";

    /// <summary>
    /// Formats the identification line without the trailing CRLF.
    /// </summary>
    /// <returns>The <c>SSH-protoversion-softwareversion[ comments]</c> line.</returns>
    public override string ToString()
    {
        string core = $"SSH-{ProtocolVersion}-{SoftwareVersion}";
        return string.IsNullOrEmpty(Comments) ? core : $"{core} {Comments}";
    }

    /// <summary>
    /// Encodes the identification line followed by CRLF, as written to the wire.
    /// </summary>
    /// <returns>The ASCII bytes of the line plus CRLF.</returns>
    public byte[] ToWireBytes()
    {
        return Encoding.ASCII.GetBytes(ToString() + "\r\n");
    }

    /// <summary>
    /// Attempts to parse an identification line (with any trailing CR/LF already removed).
    /// </summary>
    /// <param name="line">The candidate line.</param>
    /// <param name="identification">The parsed identification on success.</param>
    /// <returns>True when the line is a well-formed <c>SSH-x-y</c> identification string.</returns>
    public static bool TryParse(string line, out SshIdentificationString identification)
    {
        identification = default;
        if (string.IsNullOrEmpty(line) || !line.StartsWith("SSH-", StringComparison.Ordinal))
        {
            return false;
        }

        int secondHyphen = line.IndexOf('-', 4);
        if (secondHyphen < 0)
        {
            return false;
        }

        string protocolVersion = line.Substring(4, secondHyphen - 4);
        if (protocolVersion.Length == 0)
        {
            return false;
        }

        string remainder = line.Substring(secondHyphen + 1);
        if (remainder.Length == 0)
        {
            return false;
        }

        int space = remainder.IndexOf(' ');
        string softwareVersion = space < 0 ? remainder : remainder.Substring(0, space);
        string? comments = space < 0 ? null : remainder.Substring(space + 1);
        if (softwareVersion.Length == 0)
        {
            return false;
        }

        try
        {
            identification = new SshIdentificationString(protocolVersion, softwareVersion, comments);
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static void ValidateSoftwareVersion(string softwareVersion)
    {
        foreach (char c in softwareVersion)
        {
            if (c == ' ' || c == '-')
            {
                throw new ArgumentException(
                    "Software version must not contain a space or minus sign (RFC 4253 §4.2).",
                    nameof(softwareVersion));
            }
        }
        ValidatePrintableAscii(softwareVersion, nameof(softwareVersion));
    }

    private static void ValidatePrintableAscii(string value, string parameterName)
    {
        foreach (char c in value)
        {
            if (c < ' ' || c > (char)0x7E)
            {
                throw new ArgumentException(
                    "Identification strings must be printable US-ASCII with no control characters (RFC 4253 §4.2).",
                    parameterName);
            }
        }
    }
}
