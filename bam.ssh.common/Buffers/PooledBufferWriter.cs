using System.Buffers;
using System.Security.Cryptography;

namespace Bam.Ssh;

/// <summary>
/// An <see cref="IBufferWriter{T}"/> backed by a pooled array that grows as needed and zeroes its
/// contents when disposed. Used to stage framed or transformed packet bytes contiguously — for
/// example the cleartext frame a cipher must encrypt — without per-packet heap allocation.
/// Treat as an owned resource: dispose exactly once; the written region is invalidated on dispose.
/// </summary>
public sealed class PooledBufferWriter : IBufferWriter<byte>, IDisposable
{
    private byte[] _array;
    private int _written;
    private bool _disposed;

    /// <summary>
    /// Initializes a writer with an initial capacity rented from the shared pool.
    /// </summary>
    /// <param name="initialCapacity">The initial capacity hint in bytes. Must be non-negative.</param>
    /// <exception cref="ArgumentOutOfRangeException">The capacity is negative.</exception>
    public PooledBufferWriter(int initialCapacity = 256)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(initialCapacity);
        _array = ArrayPool<byte>.Shared.Rent(Math.Max(initialCapacity, 16));
        _written = 0;
    }

    /// <summary>
    /// Gets the number of bytes written so far.
    /// </summary>
    public int WrittenCount => _written;

    /// <summary>
    /// Gets the written bytes as a span.
    /// </summary>
    public ReadOnlySpan<byte> WrittenSpan => _array.AsSpan(0, _written);

    /// <summary>
    /// Gets the written bytes as memory.
    /// </summary>
    public ReadOnlyMemory<byte> WrittenMemory => _array.AsMemory(0, _written);

    /// <summary>
    /// Advances the write position by the given count after writing into a span or memory obtained
    /// from <see cref="GetSpan"/> or <see cref="GetMemory"/>.
    /// </summary>
    /// <param name="count">The number of bytes written.</param>
    /// <exception cref="ArgumentOutOfRangeException">The count is negative or exceeds the available capacity.</exception>
    public void Advance(int count)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(count, _array.Length - _written);
        _written += count;
    }

    /// <summary>
    /// Returns a memory buffer of at least the requested size to write into.
    /// </summary>
    /// <param name="sizeHint">The minimum number of bytes required; 0 requests a non-empty buffer.</param>
    /// <returns>A memory buffer with at least <paramref name="sizeHint"/> bytes available.</returns>
    public Memory<byte> GetMemory(int sizeHint = 0)
    {
        EnsureCapacity(sizeHint);
        return _array.AsMemory(_written);
    }

    /// <summary>
    /// Returns a span of at least the requested size to write into.
    /// </summary>
    /// <param name="sizeHint">The minimum number of bytes required; 0 requests a non-empty buffer.</param>
    /// <returns>A span with at least <paramref name="sizeHint"/> bytes available.</returns>
    public Span<byte> GetSpan(int sizeHint = 0)
    {
        EnsureCapacity(sizeHint);
        return _array.AsSpan(_written);
    }

    /// <summary>
    /// Resets the write position to zero without releasing the underlying buffer, so the writer can
    /// be reused for another packet. Zeroes the previously written region.
    /// </summary>
    public void Reset()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        CryptographicOperations.ZeroMemory(_array.AsSpan(0, _written));
        _written = 0;
    }

    /// <summary>
    /// Zeroes the written region and returns the buffer to the pool.
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        CryptographicOperations.ZeroMemory(_array.AsSpan(0, _written));
        ArrayPool<byte>.Shared.Return(_array);
        _array = Array.Empty<byte>();
        _written = 0;
    }

    private void EnsureCapacity(int sizeHint)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        int required = sizeHint <= 0 ? 1 : sizeHint;
        if (_array.Length - _written >= required)
        {
            return;
        }
        int newSize = Math.Max(_array.Length * 2, _written + required);
        byte[] grown = ArrayPool<byte>.Shared.Rent(newSize);
        _array.AsSpan(0, _written).CopyTo(grown);
        CryptographicOperations.ZeroMemory(_array.AsSpan(0, _written));
        ArrayPool<byte>.Shared.Return(_array);
        _array = grown;
    }
}
