using System.Text;

namespace Bam.Ssh;

/// <summary>
/// An immutable RFC 4251 §5 name-list value: an ordered, comma-separated list of printable
/// US-ASCII names. Order is significant — algorithm negotiation (RFC 4253 §7.1) treats earlier
/// names as preferred. Construction validates every name so encoders can trust instances without
/// re-checking. Equality is ordinal and order-sensitive.
/// </summary>
public readonly struct SshNameList : IEquatable<SshNameList>
{
    private static readonly string[] NoNames = Array.Empty<string>();

    private readonly string[]? _names;

    /// <summary>
    /// The empty name-list (encodes as a zero-length string on the wire).
    /// </summary>
    public static readonly SshNameList Empty = new SshNameList();

    /// <summary>
    /// Initializes a name-list from the given names, in preference order.
    /// Each name must be non-empty printable US-ASCII and must not contain a comma.
    /// </summary>
    /// <param name="names">The names, most preferred first.</param>
    /// <exception cref="ArgumentException">A name is null, empty, contains a comma, or contains a non-printable or non-ASCII character.</exception>
    public SshNameList(params string[] names)
    {
        ArgumentNullException.ThrowIfNull(names);
        string[] copy = new string[names.Length];
        for (int i = 0; i < names.Length; i++)
        {
            string name = names[i];
            ValidateName(name);
            copy[i] = name;
        }
        _names = copy;
    }

    /// <summary>
    /// Gets the names in preference order. Never null; empty for <see cref="Empty"/>.
    /// </summary>
    public IReadOnlyList<string> Names => _names ?? NoNames;

    /// <summary>
    /// Gets the number of names in the list.
    /// </summary>
    public int Count => _names is null ? 0 : _names.Length;

    /// <summary>
    /// Gets the name at the given preference position (0 = most preferred).
    /// </summary>
    /// <param name="index">The zero-based position.</param>
    public string this[int index] => Names[index];

    /// <summary>
    /// Determines whether the list contains the given name (ordinal comparison).
    /// </summary>
    /// <param name="name">The name to look for.</param>
    /// <returns>True when present.</returns>
    public bool Contains(string name)
    {
        string[]? names = _names;
        if (names is null)
        {
            return false;
        }
        for (int i = 0; i < names.Length; i++)
        {
            if (string.Equals(names[i], name, StringComparison.Ordinal))
            {
                return true;
            }
        }
        return false;
    }

    /// <summary>
    /// Finds the first name in this list (in this list's preference order) that also appears in
    /// <paramref name="other"/> — the RFC 4253 §7.1 negotiation rule where this list is the
    /// client's and <paramref name="other"/> is the server's.
    /// </summary>
    /// <param name="other">The peer's name-list.</param>
    /// <param name="match">The negotiated name when found; empty string otherwise.</param>
    /// <returns>True when a common name exists.</returns>
    public bool TryFindFirstCommon(SshNameList other, out string match)
    {
        string[]? names = _names;
        if (names is not null)
        {
            for (int i = 0; i < names.Length; i++)
            {
                if (other.Contains(names[i]))
                {
                    match = names[i];
                    return true;
                }
            }
        }
        match = string.Empty;
        return false;
    }

    /// <summary>
    /// Parses the wire form of a name-list (the contents of the RFC 4251 string, without the
    /// length prefix). An empty span yields <see cref="Empty"/>.
    /// </summary>
    /// <param name="encoded">The comma-separated ASCII bytes.</param>
    /// <returns>The parsed name-list.</returns>
    /// <exception cref="SshWireFormatException">The bytes contain an empty name, a leading or trailing comma, or a non-printable or non-ASCII character.</exception>
    public static SshNameList Parse(ReadOnlySpan<byte> encoded)
    {
        if (encoded.IsEmpty)
        {
            return Empty;
        }
        int nameCount = 1;
        for (int i = 0; i < encoded.Length; i++)
        {
            byte b = encoded[i];
            if (b == (byte)',')
            {
                nameCount++;
            }
            else if (b <= 0x20 || b >= 0x7F)
            {
                throw new SshWireFormatException($"Name-list contains a non-printable or non-ASCII byte 0x{b:x2} at offset {i}.");
            }
        }
        string[] names = new string[nameCount];
        int nameIndex = 0;
        int start = 0;
        for (int i = 0; i <= encoded.Length; i++)
        {
            if (i == encoded.Length || encoded[i] == (byte)',')
            {
                int length = i - start;
                if (length == 0)
                {
                    throw new SshWireFormatException("Name-list contains an empty name (adjacent, leading, or trailing comma).");
                }
                names[nameIndex] = Encoding.ASCII.GetString(encoded.Slice(start, length));
                nameIndex++;
                start = i + 1;
            }
        }
        return new SshNameList(names);
    }

    /// <summary>
    /// Gets the number of bytes the comma-separated body occupies on the wire
    /// (excluding the uint32 length prefix).
    /// </summary>
    /// <returns>The encoded body length in bytes.</returns>
    public int GetEncodedByteCount()
    {
        string[]? names = _names;
        if (names is null || names.Length == 0)
        {
            return 0;
        }
        int total = names.Length - 1;
        for (int i = 0; i < names.Length; i++)
        {
            total += names[i].Length;
        }
        return total;
    }

    /// <summary>
    /// Returns the comma-separated form (the wire body as text).
    /// </summary>
    public override string ToString()
    {
        return _names is null ? string.Empty : string.Join(',', _names);
    }

    /// <summary>
    /// Order-sensitive ordinal equality.
    /// </summary>
    /// <param name="other">The list to compare with.</param>
    public bool Equals(SshNameList other)
    {
        IReadOnlyList<string> mine = Names;
        IReadOnlyList<string> theirs = other.Names;
        if (mine.Count != theirs.Count)
        {
            return false;
        }
        for (int i = 0; i < mine.Count; i++)
        {
            if (!string.Equals(mine[i], theirs[i], StringComparison.Ordinal))
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>
    /// Order-sensitive ordinal equality.
    /// </summary>
    /// <param name="obj">The object to compare with.</param>
    public override bool Equals(object? obj)
    {
        return obj is SshNameList other && Equals(other);
    }

    /// <summary>
    /// Hash code consistent with <see cref="Equals(SshNameList)"/>.
    /// </summary>
    public override int GetHashCode()
    {
        HashCode hash = new HashCode();
        IReadOnlyList<string> names = Names;
        for (int i = 0; i < names.Count; i++)
        {
            hash.Add(names[i], StringComparer.Ordinal);
        }
        return hash.ToHashCode();
    }

    /// <summary>
    /// Equality operator; order-sensitive ordinal comparison.
    /// </summary>
    /// <param name="left">Left operand.</param>
    /// <param name="right">Right operand.</param>
    public static bool operator ==(SshNameList left, SshNameList right)
    {
        return left.Equals(right);
    }

    /// <summary>
    /// Inequality operator; order-sensitive ordinal comparison.
    /// </summary>
    /// <param name="left">Left operand.</param>
    /// <param name="right">Right operand.</param>
    public static bool operator !=(SshNameList left, SshNameList right)
    {
        return !left.Equals(right);
    }

    private static void ValidateName(string name)
    {
        if (string.IsNullOrEmpty(name))
        {
            throw new ArgumentException("Name-list entries must be non-empty.", nameof(name));
        }
        for (int i = 0; i < name.Length; i++)
        {
            char c = name[i];
            if (c == ',')
            {
                throw new ArgumentException($"Name-list entry '{name}' must not contain a comma.", nameof(name));
            }
            if (c <= ' ' || c >= (char)0x7F)
            {
                throw new ArgumentException($"Name-list entry '{name}' must be printable US-ASCII.", nameof(name));
            }
        }
    }
}
