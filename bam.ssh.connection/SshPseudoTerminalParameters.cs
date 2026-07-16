namespace Bam.Ssh.Connection;

/// <summary>
/// The parameters of a <c>pty-req</c> channel request (RFC 4254 §6.2): the terminal type, its
/// character and pixel dimensions, and the encoded terminal modes. The encoded modes default to a
/// single SSH_TTY_OP_END byte (no modes specified), which servers accept.
/// </summary>
public sealed class SshPseudoTerminalParameters
{
    private static readonly byte[] NoModes = new byte[] { 0 };

    /// <summary>
    /// Initializes the pseudo-terminal parameters.
    /// </summary>
    /// <param name="terminalType">The TERM environment value (e.g. <c>xterm-256color</c>).</param>
    /// <param name="columns">The terminal width in characters.</param>
    /// <param name="rows">The terminal height in rows.</param>
    /// <param name="widthPixels">The terminal width in pixels (0 when unknown).</param>
    /// <param name="heightPixels">The terminal height in pixels (0 when unknown).</param>
    /// <param name="encodedModes">The RFC 4254 §8 encoded terminal modes; defaults to no modes.</param>
    /// <exception cref="ArgumentNullException">The terminal type is null.</exception>
    public SshPseudoTerminalParameters(
        string terminalType,
        uint columns,
        uint rows,
        uint widthPixels = 0,
        uint heightPixels = 0,
        ReadOnlyMemory<byte>? encodedModes = null)
    {
        ArgumentNullException.ThrowIfNull(terminalType);
        TerminalType = terminalType;
        Columns = columns;
        Rows = rows;
        WidthPixels = widthPixels;
        HeightPixels = heightPixels;
        EncodedModes = encodedModes ?? NoModes;
    }

    /// <summary>
    /// Gets the TERM environment value.
    /// </summary>
    public string TerminalType { get; }

    /// <summary>
    /// Gets the terminal width in characters.
    /// </summary>
    public uint Columns { get; }

    /// <summary>
    /// Gets the terminal height in rows.
    /// </summary>
    public uint Rows { get; }

    /// <summary>
    /// Gets the terminal width in pixels.
    /// </summary>
    public uint WidthPixels { get; }

    /// <summary>
    /// Gets the terminal height in pixels.
    /// </summary>
    public uint HeightPixels { get; }

    /// <summary>
    /// Gets the encoded terminal modes (RFC 4254 §8).
    /// </summary>
    public ReadOnlyMemory<byte> EncodedModes { get; }
}
