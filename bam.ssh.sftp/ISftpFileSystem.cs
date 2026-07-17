namespace Bam.Ssh.Sftp;

/// <summary>
/// The server's virtual filesystem: the namespace and metadata operations an <see cref="SftpServer"/>
/// dispatches SFTP requests to. Implementations map an SFTP path to whatever backing store they wrap — an
/// in-memory tree, an OS directory, a database — and signal errors by throwing
/// <see cref="SftpStatusException"/> with a specific <see cref="SftpStatusCode"/> (e.g.
/// <see cref="SftpStatusCode.NoSuchFile"/>, <see cref="SftpStatusCode.PermissionDenied"/>). Paths are the
/// SFTP wire paths ('/'-separated, absolute by convention); canonicalization is
/// <see cref="GetRealPathAsync"/>. All operations are asynchronous and honor the cancellation token.
/// </summary>
public interface ISftpFileSystem
{
    /// <summary>
    /// Gets the attributes of a path.
    /// </summary>
    /// <param name="path">The path.</param>
    /// <param name="followSymbolicLinks">True to resolve a symbolic link to its target (stat vs. lstat).</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The path's attributes.</returns>
    /// <exception cref="SftpStatusException">The path does not exist or cannot be read.</exception>
    ValueTask<SftpFileAttributes> GetAttributesAsync(string path, bool followSymbolicLinks, CancellationToken cancellationToken = default);

    /// <summary>
    /// Sets attributes on a path (permissions, size, times).
    /// </summary>
    /// <param name="path">The path.</param>
    /// <param name="attributes">The attributes to apply (only present fields).</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <exception cref="SftpStatusException">The path does not exist or cannot be modified.</exception>
    ValueTask SetAttributesAsync(string path, SftpFileAttributes attributes, CancellationToken cancellationToken = default);

    /// <summary>
    /// Opens (or creates) a file, returning a handle for reads and writes.
    /// </summary>
    /// <param name="path">The file path.</param>
    /// <param name="flags">The open flags.</param>
    /// <param name="attributes">Attributes for a newly created file.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>An open file handle.</returns>
    /// <exception cref="SftpStatusException">The open failed (missing, exists, permission).</exception>
    ValueTask<ISftpFileHandle> OpenFileAsync(string path, SftpOpenFlags flags, SftpFileAttributes attributes, CancellationToken cancellationToken = default);

    /// <summary>
    /// Opens a directory, returning a handle to enumerate its entries.
    /// </summary>
    /// <param name="path">The directory path.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>An open directory handle.</returns>
    /// <exception cref="SftpStatusException">The directory does not exist or cannot be read.</exception>
    ValueTask<ISftpDirectoryHandle> OpenDirectoryAsync(string path, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a directory.
    /// </summary>
    /// <param name="path">The directory path.</param>
    /// <param name="attributes">Attributes for the new directory.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <exception cref="SftpStatusException">The directory could not be created.</exception>
    ValueTask MakeDirectoryAsync(string path, SftpFileAttributes attributes, CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes an empty directory.
    /// </summary>
    /// <param name="path">The directory path.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <exception cref="SftpStatusException">The directory does not exist, is not empty, or cannot be removed.</exception>
    ValueTask RemoveDirectoryAsync(string path, CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes a file.
    /// </summary>
    /// <param name="path">The file path.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <exception cref="SftpStatusException">The file does not exist or cannot be removed.</exception>
    ValueTask RemoveFileAsync(string path, CancellationToken cancellationToken = default);

    /// <summary>
    /// Renames (or moves) a file or directory.
    /// </summary>
    /// <param name="oldPath">The existing path.</param>
    /// <param name="newPath">The new path.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <exception cref="SftpStatusException">The source is missing or the destination is invalid.</exception>
    ValueTask RenameAsync(string oldPath, string newPath, CancellationToken cancellationToken = default);

    /// <summary>
    /// Canonicalizes a path to an absolute form (resolving <c>.</c>, <c>..</c>, and relative roots).
    /// </summary>
    /// <param name="path">The path to canonicalize.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The canonical absolute path.</returns>
    ValueTask<string> GetRealPathAsync(string path, CancellationToken cancellationToken = default);
}
