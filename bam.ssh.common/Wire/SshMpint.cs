namespace Bam.Ssh;

/// <summary>
/// RFC 4251 §5 mpint (multiple precision integer) encoding rules, isolated in one place:
/// two's complement, big-endian, minimal length — no unnecessary leading 0x00 or 0xFF bytes,
/// a 0x00 sign byte prepended when a positive value's high bit would otherwise read as negative,
/// and zero encoded as an empty string. The protocol only ever transmits non-negative values
/// (key exchange secrets, RSA parameters), so the primary API works in unsigned big-endian
/// magnitudes; raw two's-complement passthrough lives on the wire reader and writer for
/// RFC-example fidelity.
/// </summary>
public static class SshMpint
{
    /// <summary>
    /// Computes the number of bytes the mpint body occupies on the wire (excluding the uint32
    /// length prefix) for an unsigned big-endian magnitude: leading zero bytes are stripped and
    /// a sign byte is added when the leading remaining byte has its high bit set.
    /// </summary>
    /// <param name="unsignedMagnitude">The unsigned big-endian magnitude; may include leading zeros.</param>
    /// <returns>The encoded body length in bytes (0 for a zero value).</returns>
    public static int GetUnsignedBodyLength(ReadOnlySpan<byte> unsignedMagnitude)
    {
        ReadOnlySpan<byte> significant = StripLeadingZeros(unsignedMagnitude);
        if (significant.IsEmpty)
        {
            return 0;
        }
        return significant.Length + (((significant[0] & 0x80) != 0) ? 1 : 0);
    }

    /// <summary>
    /// Strips leading zero bytes from an unsigned big-endian magnitude, yielding the minimal
    /// significant bytes (empty for a zero value).
    /// </summary>
    /// <param name="unsignedMagnitude">The magnitude to normalize.</param>
    /// <returns>The magnitude without leading zero bytes.</returns>
    public static ReadOnlySpan<byte> StripLeadingZeros(ReadOnlySpan<byte> unsignedMagnitude)
    {
        int start = 0;
        while (start < unsignedMagnitude.Length && unsignedMagnitude[start] == 0)
        {
            start++;
        }
        return unsignedMagnitude.Slice(start);
    }

    /// <summary>
    /// Validates that a raw two's-complement mpint body (as read from the wire, without its
    /// length prefix) is minimally encoded per RFC 4251: no unnecessary leading 0x00
    /// (permitted only when the following byte has its high bit set) and no unnecessary
    /// leading 0xFF (a leading 0xFF may only precede a byte whose high bit is clear).
    /// </summary>
    /// <param name="twosComplementBody">The mpint body bytes.</param>
    /// <exception cref="SshWireFormatException">The encoding is not minimal.</exception>
    public static void ValidateMinimalEncoding(ReadOnlySpan<byte> twosComplementBody)
    {
        if (twosComplementBody.IsEmpty)
        {
            return;
        }
        byte first = twosComplementBody[0];
        if (first == 0x00 && (twosComplementBody.Length == 1 || (twosComplementBody[1] & 0x80) == 0))
        {
            throw new SshWireFormatException("mpint has an unnecessary leading 0x00 byte (non-minimal encoding).");
        }
        if (first == 0xFF && twosComplementBody.Length > 1 && (twosComplementBody[1] & 0x80) != 0)
        {
            throw new SshWireFormatException("mpint has an unnecessary leading 0xFF byte (non-minimal encoding).");
        }
    }

    /// <summary>
    /// Interprets a validated two's-complement mpint body as an unsigned magnitude:
    /// rejects negative values (the protocol never transmits them) and strips the
    /// single 0x00 sign byte when present.
    /// </summary>
    /// <param name="twosComplementBody">The mpint body bytes (already minimally encoded).</param>
    /// <returns>The unsigned big-endian magnitude (empty for zero).</returns>
    /// <exception cref="SshWireFormatException">The value is negative.</exception>
    public static ReadOnlySpan<byte> ToUnsignedMagnitude(ReadOnlySpan<byte> twosComplementBody)
    {
        if (twosComplementBody.IsEmpty)
        {
            return twosComplementBody;
        }
        if ((twosComplementBody[0] & 0x80) != 0)
        {
            throw new SshWireFormatException("mpint is negative; this protocol field requires a non-negative value.");
        }
        if (twosComplementBody[0] == 0x00)
        {
            return twosComplementBody.Slice(1);
        }
        return twosComplementBody;
    }
}
