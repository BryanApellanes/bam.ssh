using Bam.Ssh.Authentication;
using Bam.Test;

namespace Bam.Ssh.Tests.Interop
{
    /// <summary>
    /// Unit tests of the interop harness types themselves — deterministic, no OpenSSH required except where
    /// explicitly gated (workspace minting and the spawn smoke test skip cleanly when the tools are absent).
    /// </summary>
    [UnitTestMenu("InteropHarnessShould", Selector = "interop")]
    public class InteropHarnessShould : UnitTestMenuContainer
    {
        [UnitTest]
        public void DiscoverBinariesFromSearchDirectories()
        {
            When.A<OpenSshToolchain>("finds binaries in a synthesized directory and reports absences",
                () => OpenSshToolchain.Discover(new string[] { MakeFakeToolDirectory("ssh", "ssh-keygen", "sftp", "scp") }),
                (toolchain) =>
                {
                    OpenSshToolchain emptyToolchain = OpenSshToolchain.Discover(new string[] { MakeEmptyDirectory() });
                    return new DiscoveryOutcome(toolchain, emptyToolchain);
                })
            .TheTest
            .ShouldPass<DiscoveryOutcome>((because, outcome) =>
            {
                because.ItsTrue("ssh is found", outcome.Populated.SshPath != null);
                because.ItsTrue("ssh-keygen is found", outcome.Populated.KeygenPath != null);
                because.ItsTrue("client tools are reported present", outcome.Populated.HasClientTools);
                because.ItsTrue("sshd absence is reported", !outcome.Populated.HasServer);
                because.ItsTrue("an empty directory yields no client tools", !outcome.Empty.HasClientTools);
                because.ItsTrue("an empty directory yields no server", !outcome.Empty.HasServer);
                because.ItsTrue("an empty directory yields null paths", outcome.Empty.SshPath == null && outcome.Empty.SshdPath == null);
            })
            .SoBeHappy()
            .UnlessItFailed();
        }

        [UnitTest]
        public void PreferEarlierSearchDirectories()
        {
            When.A<OpenSshToolchain>("takes the first hit when a binary exists in two directories",
                () =>
                {
                    string first = MakeFakeToolDirectory("ssh");
                    string second = MakeFakeToolDirectory("ssh");
                    OpenSshToolchain toolchain = OpenSshToolchain.Discover(new string[] { first, second });
                    return toolchain;
                },
                (toolchain) => toolchain)
            .TheTest
            .ShouldPass<OpenSshToolchain>((because, toolchain) =>
            {
                because.ItsTrue("a path was found", toolchain.SshPath != null);
            })
            .SoBeHappy()
            .UnlessItFailed();
        }

        [UnitTest]
        public void MintKeysAndConfigThatOurReaderAccepts()
        {
            OpenSshToolchain toolchain = OpenSshToolchain.Discover();
            Skip.Unless(toolchain.KeygenPath != null, "ssh-keygen not found on this machine");

            When.A<OpenSshToolchain>("mints workspace keys and config files", toolchain, (discovered) =>
            {
                using InteropWorkspace workspace = new InteropWorkspace(discovered);
                workspace.WriteKnownHosts("127.0.0.1", 2222);
                string sshdConfigPath = workspace.WriteSshdConfig(2222);
                string hostAlgorithm = SshPrivateKeyReader.Read(workspace.HostKeyText).Algorithm;
                string userAlgorithm = SshPrivateKeyReader.Read(workspace.UserKeyText).Algorithm;
                string userBlobBase64 = Convert.ToBase64String(SshPrivateKeyReader.Read(workspace.UserKeyText).PublicKeyBlob.ToArray());
                return new WorkspaceOutcome(
                    File.Exists(workspace.HostKeyPath) && File.Exists(workspace.HostKeyPath + ".pub"),
                    File.Exists(workspace.UserKeyPath) && File.Exists(workspace.UserKeyPath + ".pub"),
                    File.ReadAllText(workspace.AuthorizedKeysPath),
                    workspace.UserPublicKeyText,
                    File.ReadAllText(workspace.KnownHostsPath),
                    File.ReadAllText(sshdConfigPath),
                    hostAlgorithm,
                    userAlgorithm,
                    userBlobBase64);
            })
            .TheTest
            .ShouldPass<WorkspaceOutcome>((because, outcome) =>
            {
                because.ItsTrue("the host key pair exists", outcome.HostKeyPairExists);
                because.ItsTrue("the user key pair exists", outcome.UserKeyPairExists);
                because.ItsTrue("authorized_keys holds the user public key", outcome.AuthorizedKeysText.Equals(outcome.UserPublicKeyText));
                because.ItsTrue("known_hosts uses the bracketed host:port form", outcome.KnownHostsText.StartsWith("[127.0.0.1]:2222 ssh-ed25519 "));
                because.ItsTrue("sshd_config pins the port", outcome.SshdConfigText.Contains("Port 2222"));
                because.ItsTrue("sshd_config points at the workspace host key", outcome.SshdConfigText.Contains("HostKey "));
                because.ItsTrue("sshd_config disables passwords", outcome.SshdConfigText.Contains("PasswordAuthentication no"));
                because.ItsTrue("our reader loads the real ssh-keygen host key as ed25519", outcome.HostKeyAlgorithm.Equals("ssh-ed25519"));
                because.ItsTrue("our reader loads the real ssh-keygen user key as ed25519", outcome.UserKeyAlgorithm.Equals("ssh-ed25519"));
                because.ItsTrue("the reader-derived public key blob matches ssh-keygen's .pub", outcome.UserPublicKeyText.Contains(outcome.UserBlobBase64));
            })
            .SoBeHappy()
            .UnlessItFailed();
        }

        [UnitTest]
        public void BuildStockClientArgumentsWithoutAShell()
        {
            OpenSshToolchain toolchain = OpenSshToolchain.Discover();
            Skip.Unless(toolchain.KeygenPath != null, "ssh-keygen not found on this machine");

            When.A<OpenSshToolchain>("builds the common stock-client options", toolchain, (discovered) =>
            {
                using InteropWorkspace workspace = new InteropWorkspace(discovered);
                OpenSshClientCommand clientCommand = new OpenSshClientCommand(discovered, workspace);
                List<string> options = clientCommand.CommonOptions("Ciphers=chacha20-poly1305@openssh.com");
                return new ClientArgumentsOutcome(options, workspace.UserKeyPath, workspace.KnownHostsPath);
            })
            .TheTest
            .ShouldPass<ClientArgumentsOutcome>((because, outcome) =>
            {
                because.ItsTrue("the workspace identity is used", outcome.Options.Contains(outcome.UserKeyPath));
                because.ItsTrue("the workspace known_hosts is used", outcome.Options.Contains($"UserKnownHostsFile={outcome.KnownHostsPath}"));
                because.ItsTrue("host-key checking is strict", outcome.Options.Contains("StrictHostKeyChecking=yes"));
                because.ItsTrue("batch mode prevents interactive prompts", outcome.Options.Contains("BatchMode=yes"));
                because.ItsTrue("extra options are appended", outcome.Options.Contains("Ciphers=chacha20-poly1305@openssh.com"));
            })
            .SoBeHappy()
            .UnlessItFailed();
        }

        [UnitTest]
        public void BuildSshdArgumentsForForegroundStderrLogging()
        {
            When.A<List<string>>("builds sshd spawn arguments",
                () => OpenSshDaemon.BuildArguments("/tmp/interop/sshd_config"),
                (arguments) => arguments)
            .TheTest
            .ShouldPass<List<string>>((because, arguments) =>
            {
                because.ItsTrue("sshd runs in the foreground", arguments.Contains("-D"));
                because.ItsTrue("sshd logs to stderr", arguments.Contains("-e"));
                because.ItsTrue("sshd loads the workspace config", arguments.Contains("-f") && arguments.Contains("/tmp/interop/sshd_config"));
            })
            .SoBeHappy()
            .UnlessItFailed();
        }

        [UnitTest]
        public void RunASubprocessAndCaptureItsOutcome()
        {
            OpenSshToolchain toolchain = OpenSshToolchain.Discover();
            Skip.Unless(toolchain.SshPath != null, "stock ssh not found on this machine");

            When.A<OpenSshToolchain>("spawns ssh -V and captures the result", toolchain, (discovered) =>
            {
                SubprocessResult result = SubprocessRunner.Run(discovered.SshPath!, new string[] { "-V" }, TimeSpan.FromSeconds(30));
                return result;
            })
            .TheTest
            .ShouldPass<SubprocessResult>((because, result) =>
            {
                because.ItsTrue("ssh -V exited zero", result.ExitCode == 0);
                because.ItsTrue("the run did not time out", !result.TimedOut);
                because.ItsTrue("a version banner was captured", (result.StandardError + result.StandardOutput).Contains("OpenSSH"));
            })
            .SoBeHappy()
            .UnlessItFailed();
        }

        [UnitTest]
        public void ForceSkipBothDirectionsWhenDisabledByEnvironment()
        {
            When.A<InteropGate>("skips via the environment kill switch",
                () => new InteropGate(OpenSshToolchain.Discover()),
                (gate) =>
                {
                    string? previousValue = Environment.GetEnvironmentVariable(InteropGate.InteropEnvironmentVariable);
                    try
                    {
                        Environment.SetEnvironmentVariable(InteropGate.InteropEnvironmentVariable, "off");
                        string? clientToolsReason = CatchSkipReason(gate.RequireClientTools);
                        string? serverReason = CatchSkipReason(gate.RequireServer);
                        return new ForceSkipOutcome(clientToolsReason, serverReason);
                    }
                    finally
                    {
                        Environment.SetEnvironmentVariable(InteropGate.InteropEnvironmentVariable, previousValue);
                    }
                })
            .TheTest
            .ShouldPass<ForceSkipOutcome>((because, outcome) =>
            {
                because.ItsTrue("the client-tools gate skips when disabled", outcome.ClientToolsReason != null);
                because.ItsTrue("the server gate skips when disabled", outcome.ServerReason != null);
                because.ItsTrue("the reason names the kill switch", outcome.ClientToolsReason!.Contains(InteropGate.InteropEnvironmentVariable));
            })
            .SoBeHappy()
            .UnlessItFailed();
        }

        private static string? CatchSkipReason(Action gateRequirement)
        {
            try
            {
                gateRequirement();
                return null;
            }
            catch (SkipTestException skipTestException)
            {
                return skipTestException.Reason;
            }
        }

        private static string MakeFakeToolDirectory(params string[] toolNames)
        {
            string directory = MakeEmptyDirectory();
            foreach (string toolName in toolNames)
            {
                File.WriteAllText(Path.Combine(directory, toolName + ".exe"), string.Empty);
                File.WriteAllText(Path.Combine(directory, toolName), string.Empty);
            }
            return directory;
        }

        private static string MakeEmptyDirectory()
        {
            string directory = Path.Combine(Path.GetTempPath(), "bam-ssh-interop-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            return directory;
        }

        private sealed record DiscoveryOutcome(OpenSshToolchain Populated, OpenSshToolchain Empty);

        private sealed record WorkspaceOutcome(
            bool HostKeyPairExists,
            bool UserKeyPairExists,
            string AuthorizedKeysText,
            string UserPublicKeyText,
            string KnownHostsText,
            string SshdConfigText,
            string HostKeyAlgorithm,
            string UserKeyAlgorithm,
            string UserBlobBase64);

        private sealed record ClientArgumentsOutcome(List<string> Options, string UserKeyPath, string KnownHostsPath);

        private sealed record ForceSkipOutcome(string? ClientToolsReason, string? ServerReason);
    }
}
