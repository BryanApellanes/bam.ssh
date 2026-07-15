using System.Buffers;
using System.Security.Cryptography;

namespace Bam.Ssh;

/// <summary>
/// A pooled byte buffer for sensitive intermediate material (key exchange scratch space,
/// plaintext staging). Rents from <see cref="ArrayPool{T}.Shared"/> and — unlike a raw pool
/// rental — zeroes the used region with <see cref="CryptographicOperations.ZeroMemory"/>
/// before returning the array, so secrets never linger in pooled memory.
/// Treat instances as owned resources: dispose exactly once and do not copy the struct
/// after wrapping it in a using statement.
/// </summary>
public struct SshRentedBuffer : IDisposable
{
    private byte[]? _array;
    private readonly int _length;

    private SshRentedBuffer(byte[] array, int length)
    {
        _array = array;
        _length = length;
    }

    /// <summary>
    /// Rents a buffer of at least the requested length from the shared pool.
    /// <see cref="Span"/> and <see cref="Memory"/> expose exactly <paramref name="length"/> bytes.
    /// </summary>
    /// <param name="length">The number of usable bytes required. Must be non-negative.</param>
    /// <returns>A rented buffer that zeroes its contents when disposed.</returns>
    public static SshRentedBuffer Rent(int length)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(length);
        byte[] array = ArrayPool<byte>.Shared.Rent(length);
        return new SshRentedBuffer(array, length);
    }

    /// <summary>
    /// Gets the number of usable bytes in the buffer (the length requested from <see cref="Rent"/>).
    /// </summary>
    public readonly int Length => _length;

    /// <summary>
    /// Gets the usable region as a span. Throws <see cref="ObjectDisposedException"/> after disposal.
    /// </summary>
    public readonly Span<byte> Span
    {
        get
        {
            byte[]? array = _array;
            ObjectDisposedException.ThrowIf(array is null, typeof(SshRentedBuffer));
            return array.AsSpan(0, _length);
        }
    }

    /// <summary>
    /// Gets the usable region as memory. Throws <see cref="ObjectDisposedException"/> after disposal.
    /// </summary>
    public readonly Memory<byte> Memory
    {
        get
        {
            byte[]? array = _array;
            ObjectDisposedException.ThrowIf(array is null, typeof(SshRentedBuffer));
            return array.AsMemory(0, _length);
        }
    }

    /// <summary>
    /// Zeroes the used region and returns the array to the pool. Safe to call more than once;
    /// subsequent calls are no-ops. Side effect: any span or memory previously obtained from this
    /// buffer observes the zeroed contents.
    /// </summary>
    public void Dispose()
    {
        byte[]? array = _array;
        if (array is not null)
        {
            _array = null;
            CryptographicOperations.ZeroMemory(array.AsSpan(0, _length));
            ArrayPool<byte>.Shared.Return(array);
        }
    }
}
