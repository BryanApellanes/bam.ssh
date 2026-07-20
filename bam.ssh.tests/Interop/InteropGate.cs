using Bam.Test;

namespace Bam.Ssh.Tests.Interop
{
    /// <summary>
    /// Decides run-versus-skip for an interop direction. When a direction's binaries are missing — or interop is
    /// force-disabled via the <c>BAM_SSH_INTEROP=off</c> environment variable — the requirement methods invoke
    /// bam.test's runtime skip API so the test reports a first-class Skipped result with the reason.
    /// </summary>
    public class InteropGate
    {
        /// <summary>
        /// The environment variable that force-disables both interop directions when set to <c>off</c>.
        /// </summary>
        public const string InteropEnvironmentVariable = "BAM_SSH_INTEROP";

        private readonly OpenSshToolchain _toolchain;

        /// <summary>
        /// Initializes a new instance of the <see cref="InteropGate"/> class over the specified toolchain.
        /// </summary>
        /// <param name="toolchain">The discovered OpenSSH toolchain.</param>
        public InteropGate(OpenSshToolchain toolchain)
        {
            _toolchain = toolchain;
        }

        /// <summary>
        /// Skips the current test unless the stock client tools (<c>ssh</c>, <c>sftp</c>, <c>scp</c>, <c>ssh-keygen</c>)
        /// are present and interop is not force-disabled. Direction A's gate.
        /// </summary>
        public void RequireClientTools()
        {
            RequireEnabled();
            Skip.Unless(_toolchain.HasClientTools, "stock OpenSSH client tools (ssh/sftp/scp/ssh-keygen) not found on this machine");
        }

        /// <summary>
        /// Skips the current test unless a stock <c>sshd</c> (and <c>ssh-keygen</c>) is present and interop is not
        /// force-disabled. Direction B's gate.
        /// </summary>
        public void RequireServer()
        {
            RequireEnabled();
            Skip.Unless(_toolchain.HasServer, "stock OpenSSH daemon (sshd) not found on this machine");
        }

        private static void RequireEnabled()
        {
            string? interopSetting = Environment.GetEnvironmentVariable(InteropEnvironmentVariable);
            Skip.When("off".Equals(interopSetting, StringComparison.OrdinalIgnoreCase), $"interop tests force-disabled via {InteropEnvironmentVariable}=off");
        }
    }
}
