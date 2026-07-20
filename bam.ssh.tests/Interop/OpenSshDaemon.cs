using System.Diagnostics;
using System.Net.Sockets;

namespace Bam.Ssh.Tests.Interop
{
    /// <summary>
    /// Spawns a stock <c>sshd -D</c> on an ephemeral loopback port with the workspace's host key and config
    /// (Direction B peer), waits until it is accepting connections, and kills it on dispose. Startup stderr
    /// (<c>sshd -e</c>) is retained so a refusal to start is diagnosable.
    /// </summary>
    public class OpenSshDaemon : IAsyncDisposable
    {
        private readonly OpenSshToolchain _toolchain;
        private readonly InteropWorkspace _workspace;
        private Process? _process;
        private readonly List<string> _standardError = new List<string>();

        /// <summary>
        /// Initializes a new instance of the <see cref="OpenSshDaemon"/> class.
        /// </summary>
        /// <param name="toolchain">The discovered OpenSSH toolchain providing the sshd binary.</param>
        /// <param name="workspace">The workspace providing the host key, authorized_keys, and config directory.</param>
        public OpenSshDaemon(OpenSshToolchain toolchain, InteropWorkspace workspace)
        {
            _toolchain = toolchain;
            _workspace = workspace;
        }

        /// <summary>
        /// Gets the loopback port sshd is listening on. Valid after <see cref="StartAsync"/> completes.
        /// </summary>
        public int Port { get; private set; }

        /// <summary>
        /// Gets or sets how long to wait for sshd to start accepting connections. Defaults to 15 seconds.
        /// </summary>
        public TimeSpan StartTimeout { get; set; } = TimeSpan.FromSeconds(15);

        /// <summary>
        /// Gets everything sshd has written to standard error, for startup-failure diagnostics.
        /// </summary>
        public string StandardError
        {
            get
            {
                lock (_standardError)
                {
                    return string.Join(Environment.NewLine, _standardError);
                }
            }
        }

        /// <summary>
        /// Builds the argument list used to spawn sshd, for construction-only unit testing.
        /// </summary>
        /// <param name="configPath">The absolute path of the sshd_config to load.</param>
        /// <returns>The argument list.</returns>
        public static List<string> BuildArguments(string configPath)
        {
            return new List<string> { "-D", "-e", "-f", configPath };
        }

        /// <summary>
        /// Reserves an ephemeral loopback port, writes the workspace sshd_config for it, spawns <c>sshd -D -e -f</c>,
        /// and waits until the port accepts a TCP connection.
        /// </summary>
        /// <returns>A task that completes when sshd is accepting connections.</returns>
        /// <exception cref="InvalidOperationException">sshd exited or never started listening within <see cref="StartTimeout"/>; the message includes sshd's stderr.</exception>
        public async ValueTask StartAsync()
        {
            Port = ReserveEphemeralPort();
            string configPath = _workspace.WriteSshdConfig(Port);

            ProcessStartInfo startInfo = new ProcessStartInfo
            {
                FileName = _toolchain.SshdPath!,
                UseShellExecute = false,
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            };
            foreach (string argument in BuildArguments(configPath))
            {
                startInfo.ArgumentList.Add(argument);
            }

            _process = new Process { StartInfo = startInfo };
            _process.ErrorDataReceived += (sender, e) => { if (e.Data != null) { lock (_standardError) { _standardError.Add(e.Data); } } };
            _process.Start();
            _process.BeginErrorReadLine();

            DateTime deadline = DateTime.UtcNow.Add(StartTimeout);
            while (DateTime.UtcNow < deadline)
            {
                if (_process.HasExited)
                {
                    throw new InvalidOperationException($"sshd exited with code {_process.ExitCode} before listening. stderr: {StandardError}");
                }
                if (await CanConnectAsync())
                {
                    return;
                }
                await Task.Delay(100);
            }
            throw new InvalidOperationException($"sshd did not start listening on port {Port} within {StartTimeout}. stderr: {StandardError}");
        }

        /// <summary>
        /// Kills the spawned sshd (and its children) if it is still running.
        /// </summary>
        /// <returns>A task that completes when the process has exited.</returns>
        public ValueTask DisposeAsync()
        {
            if (_process != null && !_process.HasExited)
            {
                try
                {
                    _process.Kill(entireProcessTree: true);
                    _process.WaitForExit();
                }
                catch (InvalidOperationException)
                {
                    // The process exited between the check and the kill.
                }
            }
            _process?.Dispose();
            _process = null;
            return ValueTask.CompletedTask;
        }

        private async Task<bool> CanConnectAsync()
        {
            try
            {
                using TcpClient tcpClient = new TcpClient();
                await tcpClient.ConnectAsync("127.0.0.1", Port).WaitAsync(TimeSpan.FromSeconds(1));
                return true;
            }
            catch (SocketException)
            {
                return false;
            }
            catch (TimeoutException)
            {
                return false;
            }
        }

        private static int ReserveEphemeralPort()
        {
            TcpListener tcpListener = new TcpListener(System.Net.IPAddress.Loopback, 0);
            tcpListener.Start();
            int port = ((System.Net.IPEndPoint)tcpListener.LocalEndpoint).Port;
            tcpListener.Stop();
            return port;
        }
    }
}
