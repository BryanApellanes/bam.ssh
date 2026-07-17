namespace Bam.Ssh.Sftp;

/// <summary>
/// An open directory returned by <see cref="ISftpFileSystem.OpenDirectoryAsync"/>. SFTP enumerates a
/// directory by repeated READDIR calls until the server reports EOF, so the handle yields the next batch of
/// entries each call and an empty batch when enumeration is complete. Disposing releases the resource.
/// </summary>
public interface ISftpDirectoryHandle : IAsyncDisposable
{
    /// <summary>
    /// Reads the next batch of directory entries.
    /// </summary>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>The next entries, or an empty list when enumeration is complete.</returns>
    ValueTask<IReadOnlyList<SftpName>> ReadAsync(CancellationToken cancellationToken = default);
}
