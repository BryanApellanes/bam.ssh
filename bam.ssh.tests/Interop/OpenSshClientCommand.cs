namespace Bam.Ssh.Tests.Interop
{
    /// <summary>
    /// Builds and runs stock <c>ssh</c>/<c>sftp</c>/<c>scp</c> invocations against a server under test, using the
    /// workspace's identity and known_hosts material, and captures the outcome. Arguments are passed as a list —
    /// never through a shell — and every run is bounded by <see cref="Timeout"/>.
    /// </summary>
    public class OpenSshClientCommand
    {
        private readonly OpenSshToolchain _toolchain;
        private readonly InteropWorkspace _workspace;

        /// <summary>
        /// Initializes a new instance of the <see cref="OpenSshClientCommand"/> class.
        /// </summary>
        /// <param name="toolchain">The discovered OpenSSH toolchain providing the client binaries.</param>
        /// <param name="workspace">The workspace providing identity, known_hosts, and scratch files.</param>
        public OpenSshClientCommand(OpenSshToolchain toolchain, InteropWorkspace workspace)
        {
            _toolchain = toolchain;
            _workspace = workspace;
        }

        /// <summary>
        /// Gets or sets the user name presented to the server. Defaults to <c>interop</c>.
        /// </summary>
        public string User { get; set; } = "interop";

        /// <summary>
        /// Gets or sets the hard timeout applied to every subprocess run. Defaults to 30 seconds.
        /// </summary>
        public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>
        /// Runs <c>ssh user@host -p port command</c> with the workspace identity and strict host-key checking
        /// against the workspace known_hosts.
        /// </summary>
        /// <param name="host">The server host, typically 127.0.0.1.</param>
        /// <param name="port">The server port.</param>
        /// <param name="command">The remote command to execute.</param>
        /// <param name="extraOptions">Additional <c>-o</c> option values (e.g. <c>Ciphers=chacha20-poly1305@openssh.com</c>).</param>
        /// <returns>The captured result.</returns>
        public SubprocessResult Exec(string host, int port, string command, params string[] extraOptions)
        {
            List<string> arguments = CommonOptions(extraOptions);
            arguments.Add("-p");
            arguments.Add(port.ToString());
            arguments.Add($"{User}@{host}");
            arguments.Add(command);
            return SubprocessRunner.Run(_toolchain.SshPath!, arguments, Timeout);
        }

        /// <summary>
        /// Runs <c>sftp -b</c> with the specified batch commands (one per line) against the server.
        /// </summary>
        /// <param name="host">The server host, typically 127.0.0.1.</param>
        /// <param name="port">The server port.</param>
        /// <param name="batchCommands">The sftp batch commands, e.g. <c>put local remote</c>, <c>get remote local</c>.</param>
        /// <param name="extraOptions">Additional <c>-o</c> option values.</param>
        /// <returns>The captured result.</returns>
        public SubprocessResult Sftp(string host, int port, IEnumerable<string> batchCommands, params string[] extraOptions)
        {
            string batchPath = _workspace.WriteScratchFile("sftp-batch.txt", string.Join('\n', batchCommands) + "\n");
            List<string> arguments = CommonOptions(extraOptions);
            arguments.Add("-b");
            arguments.Add(batchPath);
            arguments.Add("-P");
            arguments.Add(port.ToString());
            arguments.Add($"{User}@{host}");
            return SubprocessRunner.Run(_toolchain.SftpPath!, arguments, Timeout);
        }

        /// <summary>
        /// Runs <c>scp</c> with the specified source and destination. Remote specs should use the
        /// <c>user@host:path</c> form produced by <see cref="RemoteSpec"/>.
        /// </summary>
        /// <param name="port">The server port.</param>
        /// <param name="source">The source path or remote spec.</param>
        /// <param name="destination">The destination path or remote spec.</param>
        /// <param name="extraOptions">Additional <c>-o</c> option values.</param>
        /// <returns>The captured result.</returns>
        public SubprocessResult Scp(int port, string source, string destination, params string[] extraOptions)
        {
            List<string> arguments = CommonOptions(extraOptions);
            arguments.Add("-P");
            arguments.Add(port.ToString());
            arguments.Add(source);
            arguments.Add(destination);
            return SubprocessRunner.Run(_toolchain.ScpPath!, arguments, Timeout);
        }

        /// <summary>
        /// Builds a remote path spec (<c>user@host:path</c>) for <see cref="Scp"/>.
        /// </summary>
        /// <param name="host">The server host.</param>
        /// <param name="remotePath">The path on the server.</param>
        /// <returns>The remote spec.</returns>
        public string RemoteSpec(string host, string remotePath)
        {
            return $"{User}@{host}:{remotePath}";
        }

        /// <summary>
        /// Builds the option list shared by every invocation: workspace identity only, strict host-key checking
        /// against the workspace known_hosts, batch mode (no prompts), and a bounded connect timeout.
        /// </summary>
        /// <param name="extraOptions">Additional <c>-o</c> option values appended after the common ones.</param>
        /// <returns>The argument list to extend with command-specific arguments.</returns>
        public List<string> CommonOptions(params string[] extraOptions)
        {
            List<string> arguments = new List<string>
            {
                "-i", _workspace.UserKeyPath,
                "-F", "none",
                "-o", $"UserKnownHostsFile={_workspace.KnownHostsPath}",
                "-o", "StrictHostKeyChecking=yes",
                "-o", "IdentitiesOnly=yes",
                "-o", "BatchMode=yes",
                "-o", "ConnectTimeout=10"
            };
            foreach (string extraOption in extraOptions)
            {
                arguments.Add("-o");
                arguments.Add(extraOption);
            }
            return arguments;
        }
    }
}
