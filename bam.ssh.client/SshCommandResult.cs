using System.Text;

namespace Bam.Ssh.Client;

/// <summary>
/// The outcome of running a remote command with <see cref="SshClient.ExecuteAsync"/>: the exit code (if
/// the server reported one) and the captured standard-output and standard-error byte streams.
/// </summary>
public sealed class SshCommandResult
{
    /// <summary>
    /// Initializes the result.
    /// </summary>
    /// <param name="exitCode">The remote command's exit code, or null if the server did not report one.</param>
    /// <param name="standardOutput">The captured standard-output bytes.</param>
    /// <param name="standardError">The captured standard-error bytes.</param>
    /// <exception cref="ArgumentNullException">An output buffer is null.</exception>
    public SshCommandResult(int? exitCode, byte[] standardOutput, byte[] standardError)
    {
        ArgumentNullException.ThrowIfNull(standardOutput);
        ArgumentNullException.ThrowIfNull(standardError);
        ExitCode = exitCode;
        StandardOutput = standardOutput;
        StandardError = standardError;
    }

    /// <summary>
    /// Gets the remote command's exit code, or null if the server did not report one.
    /// </summary>
    public int? ExitCode { get; }

    /// <summary>
    /// Gets the captured standard-output bytes.
    /// </summary>
    public byte[] StandardOutput { get; }

    /// <summary>
    /// Gets the captured standard-error bytes.
    /// </summary>
    public byte[] StandardError { get; }

    /// <summary>
    /// Gets the standard output decoded as UTF-8 text.
    /// </summary>
    public string StandardOutputText => Encoding.UTF8.GetString(StandardOutput);

    /// <summary>
    /// Gets the standard error decoded as UTF-8 text.
    /// </summary>
    public string StandardErrorText => Encoding.UTF8.GetString(StandardError);
}
