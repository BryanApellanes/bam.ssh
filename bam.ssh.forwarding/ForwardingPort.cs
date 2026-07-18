namespace Bam.Ssh.Forwarding;

/// <summary>
/// Validates that a value is a legal TCP port number (0–65535). Forwarding records carry ports as uint32 on
/// the wire, but only 0–65535 are meaningful.
/// </summary>
internal static class ForwardingPort
{
    public static void Validate(int port, [System.Runtime.CompilerServices.CallerArgumentExpression(nameof(port))] string? paramName = null)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(port, paramName);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(port, 65535, paramName);
    }
}
