using System.Runtime.InteropServices;

namespace Bam.Ssh.Tests.Interop
{
    /// <summary>
    /// Locates the stock OpenSSH binaries on the current machine and reports which interop directions can run:
    /// Direction A (our server ↔ stock clients) needs the client tools; Direction B (our client ↔ stock sshd) needs the daemon.
    /// </summary>
    public class OpenSshToolchain
    {
        /// <summary>
        /// Gets or sets the full path of the stock <c>ssh</c> client, or null when not found.
        /// </summary>
        public string? SshPath { get; set; }

        /// <summary>
        /// Gets or sets the full path of the stock <c>sshd</c> daemon, or null when not found.
        /// </summary>
        public string? SshdPath { get; set; }

        /// <summary>
        /// Gets or sets the full path of <c>ssh-keygen</c>, or null when not found.
        /// </summary>
        public string? KeygenPath { get; set; }

        /// <summary>
        /// Gets or sets the full path of the stock <c>sftp</c> client, or null when not found.
        /// </summary>
        public string? SftpPath { get; set; }

        /// <summary>
        /// Gets or sets the full path of the stock <c>scp</c> client, or null when not found.
        /// </summary>
        public string? ScpPath { get; set; }

        /// <summary>
        /// Gets a value indicating whether the client-side tools needed by Direction A (<c>ssh</c>, <c>sftp</c>, <c>scp</c>)
        /// and key minting (<c>ssh-keygen</c>) were all found.
        /// </summary>
        public bool HasClientTools => SshPath != null && SftpPath != null && ScpPath != null && KeygenPath != null;

        /// <summary>
        /// Gets a value indicating whether the daemon needed by Direction B (<c>sshd</c>) and key minting (<c>ssh-keygen</c>) were found.
        /// </summary>
        public bool HasServer => SshdPath != null && KeygenPath != null;

        /// <summary>
        /// Discovers the OpenSSH binaries in the platform's well-known install locations followed by the directories on PATH.
        /// On Windows the native <c>C:\Windows\System32\OpenSSH</c> build is preferred over any MSYS/Git-Bash copy on PATH,
        /// because the native build handles Windows paths without translation surprises.
        /// </summary>
        /// <returns>A populated <see cref="OpenSshToolchain"/>.</returns>
        public static OpenSshToolchain Discover()
        {
            List<string> searchDirectories = new List<string>();
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                string systemRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                searchDirectories.Add(Path.Combine(systemRoot, "System32", "OpenSSH"));
            }
            else
            {
                // sshd conventionally lives in sbin directories that are often absent from PATH.
                searchDirectories.Add("/usr/sbin");
                searchDirectories.Add("/usr/local/sbin");
            }
            string pathVariable = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
            searchDirectories.AddRange(pathVariable.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries));
            return Discover(searchDirectories);
        }

        /// <summary>
        /// Discovers the OpenSSH binaries by probing the specified directories in order; the first hit for each binary wins.
        /// </summary>
        /// <param name="searchDirectories">The directories to probe, highest precedence first.</param>
        /// <returns>A populated <see cref="OpenSshToolchain"/>.</returns>
        public static OpenSshToolchain Discover(IEnumerable<string> searchDirectories)
        {
            List<string> directories = searchDirectories.ToList();
            return new OpenSshToolchain
            {
                SshPath = FindExecutable(directories, "ssh"),
                SshdPath = FindExecutable(directories, "sshd"),
                KeygenPath = FindExecutable(directories, "ssh-keygen"),
                SftpPath = FindExecutable(directories, "sftp"),
                ScpPath = FindExecutable(directories, "scp")
            };
        }

        private static string? FindExecutable(List<string> directories, string name)
        {
            foreach (string directory in directories)
            {
                string bare = Path.Combine(directory, name);
                string withExe = bare + ".exe";
                if (File.Exists(withExe))
                {
                    return withExe;
                }
                if (File.Exists(bare))
                {
                    return bare;
                }
            }
            return null;
        }
    }
}
