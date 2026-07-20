namespace Bam.Ssh.Tests.Interop
{
    /// <summary>
    /// Captured outcome of a completed (or timed-out) subprocess run.
    /// </summary>
    public class SubprocessResult
    {
        /// <summary>
        /// Gets or sets the process exit code. Meaningless when <see cref="TimedOut"/> is true.
        /// </summary>
        public int ExitCode { get; set; }

        /// <summary>
        /// Gets or sets everything the process wrote to standard output.
        /// </summary>
        public string StandardOutput { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets everything the process wrote to standard error.
        /// </summary>
        public string StandardError { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets a value indicating whether the process exceeded its timeout and was killed.
        /// </summary>
        public bool TimedOut { get; set; }

        /// <summary>
        /// Gets a value indicating whether the process exited on its own with exit code zero.
        /// </summary>
        public bool Succeeded => !TimedOut && ExitCode == 0;
    }
}
