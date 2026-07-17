namespace Bam.Ssh.Sftp;

/// <summary>
/// An open file returned by <see cref="ISftpFileSystem.OpenFileAsync"/>. SFTP reads and writes are
/// positional (each carries an explicit offset), so the handle is stateless with respect to a file
/// pointer. Disposing releases the underlying resource.
/// </summary>
public interface ISftpFileHandle : IAsyncDisposable
{
    /// <summary>
    /// Reads up to <paramref name="buffer"/>.Length bytes starting at the given offset.
    /// </summary>
    /// <param name="offset">The byte offset to read from.</param>
    /// <param name="buffer">The destination buffer.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>The number of bytes read, or zero at end of file.</returns>
    ValueTask<int> ReadAsync(ulong offset, Memory<byte> buffer, CancellationToken cancellationToken = default);

    /// <summary>
    /// Writes the data starting at the given offset.
    /// </summary>
    /// <param name="offset">The byte offset to write at.</param>
    /// <param name="data">The bytes to write.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    ValueTask WriteAsync(ulong offset, ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets the file's current attributes.
    /// </summary>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The file's attributes.</returns>
    ValueTask<SftpFileAttributes> GetAttributesAsync(CancellationToken cancellationToken = default);
}
