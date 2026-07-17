namespace Bam.Ssh.Scp;

/// <summary>
/// The kind of SCP control record, discriminated by its leading byte on the wire.
/// </summary>
public enum ScpControlType
{
    /// <summary>A file record (<c>C</c>): mode, size, and name, followed by that many data bytes.</summary>
    File,

    /// <summary>A directory-start record (<c>D</c>): mode and name; entries follow until the matching <c>E</c>.</summary>
    Directory,

    /// <summary>A directory-end record (<c>E</c>): pops one level of the recursive descent.</summary>
    EndDirectory,

    /// <summary>A timestamps record (<c>T</c>): modify and access times for the next file or directory.</summary>
    Time,
}
