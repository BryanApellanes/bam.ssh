using Bam.Ssh.Authentication;
using Bam.Ssh.Client;
using Bam.Ssh.Connection;
using Bam.Ssh.Sftp;
using Bam.Test;

namespace Bam.Ssh.Tests.Interop
{
    /// <summary>
    /// Direction B interop: our production SshClient driving a STOCK OpenSSH sshd spawned on an ephemeral loopback
    /// port. Host-key trust is via KnownHostsHostKeyVerifier in Strict mode against the workspace known_hosts, so
    /// our known_hosts parsing is exercised against a real sshd host key. Skips (via bam.test's runtime skip) where
    /// sshd is not installed — e.g. this suite runs on the Linux CI job and under WSL, and skips on a plain
    /// Windows dev box.
    /// </summary>
    [UnitTestMenu("StockSshdInteropShould", Selector = "interop")]
    public class StockSshdInteropShould : UnitTestMenuContainer
    {
        [UnitTest]
        public void ExecuteACommandAgainstTheStockSshd()
        {
            OpenSshToolchain toolchain = OpenSshToolchain.Discover();
            new InteropGate(toolchain).RequireServer();

            When.A<OpenSshToolchain>("executes a command against a stock sshd", toolchain, (discovered) =>
            {
                using InteropWorkspace workspace = new InteropWorkspace(discovered);
                return RunExecAsync(discovered, workspace).GetAwaiter().GetResult();
            })
            .TheTest
            .ShouldPass<StockSshdExecOutcome>((because, outcome) =>
            {
                because.ItsTrue("the command exited zero", outcome.ExitCode == 0);
                because.ItsTrue("the command output round-tripped", outcome.StandardOutput.Trim().Equals("interop-direction-b"));
            })
            .SoBeHappy()
            .UnlessItFailed();
        }

        [UnitTest]
        public void RoundTripAFileOverSftpAgainstTheStockSshd()
        {
            OpenSshToolchain toolchain = OpenSshToolchain.Discover();
            new InteropGate(toolchain).RequireServer();

            When.A<OpenSshToolchain>("round-trips a file over SFTP against a stock sshd", toolchain, (discovered) =>
            {
                using InteropWorkspace workspace = new InteropWorkspace(discovered);
                return RunSftpRoundTripAsync(discovered, workspace).GetAwaiter().GetResult();
            })
            .TheTest
            .ShouldPass<StockSshdSftpOutcome>((because, outcome) =>
            {
                because.ItsTrue("the downloaded bytes equal the uploaded bytes", outcome.DownloadedBytes.SequenceEqual(outcome.UploadedBytes));
            })
            .SoBeHappy()
            .UnlessItFailed();
        }

        private static async Task<StockSshdExecOutcome> RunExecAsync(OpenSshToolchain toolchain, InteropWorkspace workspace)
        {
            await using OpenSshDaemon daemon = new OpenSshDaemon(toolchain, workspace);
            await daemon.StartAsync();
            workspace.WriteKnownHosts("127.0.0.1", daemon.Port);

            await using SshClient client = NewClient(workspace);
            await client.ConnectAsync("127.0.0.1", daemon.Port);
            await client.AuthenticateWithPublicKeyAsync(Environment.UserName, SshPrivateKeyReader.Read(workspace.UserKeyText));
            SshCommandResult result = await client.ExecuteAsync("echo interop-direction-b");
            return new StockSshdExecOutcome(result.ExitCode, result.StandardOutputText, result.StandardErrorText);
        }

        private static async Task<StockSshdSftpOutcome> RunSftpRoundTripAsync(OpenSshToolchain toolchain, InteropWorkspace workspace)
        {
            await using OpenSshDaemon daemon = new OpenSshDaemon(toolchain, workspace);
            await daemon.StartAsync();
            workspace.WriteKnownHosts("127.0.0.1", daemon.Port);

            await using SshClient client = NewClient(workspace);
            await client.ConnectAsync("127.0.0.1", daemon.Port);
            await client.AuthenticateWithPublicKeyAsync(Environment.UserName, SshPrivateKeyReader.Read(workspace.UserKeyText));

            byte[] payload = new byte[32 * 1024 + 5];
            for (int i = 0; i < payload.Length; i++)
            {
                payload[i] = (byte)(i % 249);
            }
            string remotePath = $"{workspace.Root.Replace('\\', '/')}/sftp-direction-b.bin";

            SshSessionChannel channel = await client.OpenSessionChannelAsync();
            await using SftpClient sftpClient = await SftpClient.OpenAsync(channel);
            await sftpClient.UploadAsync(remotePath, payload);
            byte[] downloaded = await sftpClient.DownloadAsync(remotePath);
            return new StockSshdSftpOutcome(payload, downloaded);
        }

        /// <summary>
        /// Builds our production client trusting exactly the workspace known_hosts entry (Strict mode) — the real
        /// sshd host key must match what ssh-keygen minted, exercising our known_hosts verification against an
        /// independent implementation.
        /// </summary>
        private static SshClient NewClient(InteropWorkspace workspace)
        {
            return new SshClient(new SshClientOptions(KnownHostsHostKeyVerifier.Strict(workspace.KnownHostsPath)));
        }

        private sealed record StockSshdExecOutcome(int? ExitCode, string StandardOutput, string StandardError);

        private sealed record StockSshdSftpOutcome(byte[] UploadedBytes, byte[] DownloadedBytes);
    }
}
