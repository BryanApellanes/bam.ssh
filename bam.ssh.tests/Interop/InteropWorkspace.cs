using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Bam.Ssh.Tests.Interop
{
    /// <summary>
    /// Owns a temp directory of <c>ssh-keygen</c>-minted host and user keys plus the generated
    /// <c>authorized_keys</c>/<c>known_hosts</c>/<c>sshd_config</c> files, and exposes the minted keys both as file
    /// paths (for the stock tools) and as text (for our own endpoints via <c>SshPrivateKeyReader</c>). Keys are
    /// fresh per instance and the directory is deleted on dispose — nothing is ever committed.
    /// </summary>
    public class InteropWorkspace : IDisposable
    {
        private readonly OpenSshToolchain _toolchain;

        /// <summary>
        /// Initializes a new instance of the <see cref="InteropWorkspace"/> class, creating the temp directory and
        /// minting fresh ed25519 host and user key pairs with <c>ssh-keygen</c>.
        /// </summary>
        /// <param name="toolchain">The discovered OpenSSH toolchain providing <c>ssh-keygen</c>.</param>
        /// <exception cref="InvalidOperationException">ssh-keygen failed to mint a key; the message includes its stderr.</exception>
        public InteropWorkspace(OpenSshToolchain toolchain)
        {
            _toolchain = toolchain;
            Root = Path.Combine(Path.GetTempPath(), "bam-ssh-interop", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Root);

            HostKeyPath = MintKey("host_ed25519", "bam-ssh-interop-host");
            UserKeyPath = MintKey("user_ed25519", "bam-ssh-interop-user");
            AuthorizedKeysPath = Path.Combine(Root, "authorized_keys");
            File.WriteAllText(AuthorizedKeysPath, File.ReadAllText(UserKeyPath + ".pub"));
            KnownHostsPath = Path.Combine(Root, "known_hosts");
            File.WriteAllText(KnownHostsPath, string.Empty);
            RestrictPermissions(AuthorizedKeysPath);
        }

        /// <summary>
        /// Gets the root temp directory owned by this workspace.
        /// </summary>
        public string Root { get; }

        /// <summary>
        /// Gets the path of the minted host private key; the matching public key is at this path + <c>.pub</c>.
        /// </summary>
        public string HostKeyPath { get; }

        /// <summary>
        /// Gets the path of the minted user private key; the matching public key is at this path + <c>.pub</c>.
        /// </summary>
        public string UserKeyPath { get; }

        /// <summary>
        /// Gets the path of the generated <c>authorized_keys</c> file containing the user public key.
        /// </summary>
        public string AuthorizedKeysPath { get; }

        /// <summary>
        /// Gets the path of the <c>known_hosts</c> file; content is written by <see cref="WriteKnownHosts"/> once the
        /// server port is known.
        /// </summary>
        public string KnownHostsPath { get; }

        /// <summary>
        /// Gets the text of the minted host private key, for loading into our endpoints via <c>SshPrivateKeyReader</c>.
        /// </summary>
        public string HostKeyText => File.ReadAllText(HostKeyPath);

        /// <summary>
        /// Gets the text of the minted user private key, for loading into our endpoints via <c>SshPrivateKeyReader</c>.
        /// </summary>
        public string UserKeyText => File.ReadAllText(UserKeyPath);

        /// <summary>
        /// Gets the text of the minted user public key in OpenSSH <c>authorized_keys</c> format.
        /// </summary>
        public string UserPublicKeyText => File.ReadAllText(UserKeyPath + ".pub");

        /// <summary>
        /// Gets the text of the minted host public key in OpenSSH format.
        /// </summary>
        public string HostPublicKeyText => File.ReadAllText(HostKeyPath + ".pub");

        /// <summary>
        /// Writes the <c>known_hosts</c> entry trusting the minted host key for the specified endpoint, in the
        /// bracketed non-standard-port form OpenSSH expects (<c>[host]:port keytype key</c>).
        /// </summary>
        /// <param name="host">The server host, typically 127.0.0.1.</param>
        /// <param name="port">The server port.</param>
        public void WriteKnownHosts(string host, int port)
        {
            string[] publicKeyParts = HostPublicKeyText.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            File.WriteAllText(KnownHostsPath, $"[{host}]:{port} {publicKeyParts[0]} {publicKeyParts[1]}\n");
        }

        /// <summary>
        /// Writes an <c>sshd_config</c> for a loopback sshd on the specified port: publickey-only auth against the
        /// workspace <c>authorized_keys</c>, the minted host key, in-process SFTP, and no PAM — suitable for running
        /// as an unprivileged user.
        /// </summary>
        /// <param name="port">The port sshd should listen on.</param>
        /// <returns>The path of the written config file.</returns>
        public string WriteSshdConfig(int port)
        {
            string configPath = Path.Combine(Root, "sshd_config");
            string[] configLines = new string[]
            {
                $"Port {port}",
                "ListenAddress 127.0.0.1",
                $"HostKey {HostKeyPath}",
                $"AuthorizedKeysFile {AuthorizedKeysPath}",
                "PubkeyAuthentication yes",
                "PasswordAuthentication no",
                "KbdInteractiveAuthentication no",
                "UsePAM no",
                "StrictModes no",
                $"PidFile {Path.Combine(Root, "sshd.pid")}",
                "Subsystem sftp internal-sftp",
                "LogLevel VERBOSE"
            };
            File.WriteAllText(configPath, string.Join('\n', configLines) + "\n");
            return configPath;
        }

        /// <summary>
        /// Writes a scratch file (e.g. an sftp batch script or a payload to transfer) into the workspace.
        /// </summary>
        /// <param name="fileName">The file name, relative to the workspace root.</param>
        /// <param name="content">The file content.</param>
        /// <returns>The absolute path of the written file.</returns>
        public string WriteScratchFile(string fileName, string content)
        {
            string filePath = Path.Combine(Root, fileName);
            File.WriteAllText(filePath, content);
            return filePath;
        }

        /// <summary>
        /// Deletes the workspace directory and everything in it, best-effort.
        /// </summary>
        public void Dispose()
        {
            try
            {
                Directory.Delete(Root, recursive: true);
            }
            catch (IOException)
            {
                // Best-effort cleanup; a straggling handle on Windows must not fail the suite.
            }
            catch (UnauthorizedAccessException)
            {
            }
        }

        private string MintKey(string fileName, string comment)
        {
            string keyPath = Path.Combine(Root, fileName);
            SubprocessResult result = SubprocessRunner.Run(
                _toolchain.KeygenPath!,
                new string[] { "-t", "ed25519", "-N", "", "-C", comment, "-f", keyPath },
                TimeSpan.FromSeconds(30));
            if (!result.Succeeded)
            {
                throw new InvalidOperationException($"ssh-keygen failed for {fileName}: {result.StandardError}");
            }
            RestrictPermissions(keyPath);
            return keyPath;
        }

        /// <summary>
        /// Restricts a file to the current user — OpenSSH refuses identity and key files with permissive ACLs.
        /// Uses <c>icacls</c> on Windows and owner-only Unix file mode elsewhere.
        /// </summary>
        /// <param name="filePath">The file to restrict.</param>
        private static void RestrictPermissions(string filePath)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                string userName = Environment.UserName;
                ProcessStartInfo startInfo = new ProcessStartInfo
                {
                    FileName = "icacls",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };
                startInfo.ArgumentList.Add(filePath);
                startInfo.ArgumentList.Add("/inheritance:r");
                startInfo.ArgumentList.Add("/grant:r");
                startInfo.ArgumentList.Add($"{userName}:F");
                using Process process = Process.Start(startInfo)!;
                process.WaitForExit();
            }
            else
            {
                File.SetUnixFileMode(filePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
        }
    }
}
