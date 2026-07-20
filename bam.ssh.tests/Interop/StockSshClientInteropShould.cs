using System.Net;
using Bam.Ssh.Authentication;
using Bam.Ssh.Server;
using Bam.Ssh.Sftp;
using Bam.Ssh.Tests.Unit;
using Bam.Ssh.Transport;
using Bam.Test;

namespace Bam.Ssh.Tests.Interop
{
    /// <summary>
    /// Direction A interop: our production SshServer serving the STOCK OpenSSH clients (ssh, sftp, scp) as real
    /// subprocesses over loopback TCP — the first tests where the peer is an independent SSH implementation.
    /// Skips (via bam.test's runtime skip) when the stock client tools are not installed.
    /// </summary>
    [UnitTestMenu("StockSshClientInteropShould", Selector = "interop")]
    public class StockSshClientInteropShould : UnitTestMenuContainer
    {
        /// <summary>
        /// First-cut algorithm pinning per the resolved design scope: curve25519 kex, chacha20-poly1305 cipher,
        /// ed25519 host and user keys, publickey auth.
        /// </summary>
        private static readonly string[] PinnedAlgorithms = new string[]
        {
            "KexAlgorithms=curve25519-sha256",
            "Ciphers=chacha20-poly1305@openssh.com",
            "HostKeyAlgorithms=ssh-ed25519",
            "PubkeyAcceptedAlgorithms=ssh-ed25519"
        };

        [UnitTest]
        public void ServeExecToTheStockSshClient()
        {
            OpenSshToolchain toolchain = OpenSshToolchain.Discover();
            new InteropGate(toolchain).RequireClientTools();

            When.A<OpenSshToolchain>("serves an exec request from the stock ssh client", toolchain, (discovered) =>
            {
                using InteropWorkspace workspace = new InteropWorkspace(discovered);
                return RunExecAsync(discovered, workspace).GetAwaiter().GetResult();
            })
            .TheTest
            .ShouldPass<StockClientOutcome>((because, outcome) =>
            {
                because.ItsTrue("the stock ssh client exited zero", outcome.Result.ExitCode == 0);
                because.ItsTrue("the run did not time out", !outcome.Result.TimedOut);
                because.ItsTrue("our server's stdout reached the stock client", outcome.Result.StandardOutput.Contains("interop-exec:echo interop"));
                because.AdditionalInformation($"ssh stderr: {outcome.Result.StandardError}");
            })
            .SoBeHappy()
            .UnlessItFailed();
        }

        [UnitTest]
        public void RoundTripAFileOverTheStockSftpClient()
        {
            OpenSshToolchain toolchain = OpenSshToolchain.Discover();
            new InteropGate(toolchain).RequireClientTools();

            When.A<OpenSshToolchain>("round-trips a file through our SFTP server via the stock sftp client", toolchain, (discovered) =>
            {
                using InteropWorkspace workspace = new InteropWorkspace(discovered);
                return RunSftpRoundTripAsync(discovered, workspace).GetAwaiter().GetResult();
            })
            .TheTest
            .ShouldPass<StockClientRoundTripOutcome>((because, outcome) =>
            {
                because.ItsTrue("the stock sftp client exited zero", outcome.Result.ExitCode == 0);
                because.ItsTrue("the run did not time out", !outcome.Result.TimedOut);
                because.ItsTrue("the downloaded bytes equal the uploaded bytes", outcome.DownloadedBytes.SequenceEqual(outcome.UploadedBytes));
                because.AdditionalInformation($"sftp stderr: {outcome.Result.StandardError}");
            })
            .SoBeHappy()
            .UnlessItFailed();
        }

        [UnitTest]
        public void RoundTripAFileOverTheStockScpClient()
        {
            OpenSshToolchain toolchain = OpenSshToolchain.Discover();
            new InteropGate(toolchain).RequireClientTools();

            When.A<OpenSshToolchain>("round-trips a file through our server via the stock scp client", toolchain, (discovered) =>
            {
                using InteropWorkspace workspace = new InteropWorkspace(discovered);
                return RunScpRoundTripAsync(discovered, workspace).GetAwaiter().GetResult();
            })
            .TheTest
            .ShouldPass<StockClientScpOutcome>((because, outcome) =>
            {
                because.ItsTrue("the upload scp exited zero", outcome.UploadResult.ExitCode == 0);
                because.ItsTrue("the download scp exited zero", outcome.DownloadResult.ExitCode == 0);
                because.ItsTrue("the downloaded bytes equal the uploaded bytes", outcome.DownloadedBytes.SequenceEqual(outcome.UploadedBytes));
                because.AdditionalInformation($"scp up stderr: {outcome.UploadResult.StandardError}; scp down stderr: {outcome.DownloadResult.StandardError}");
            })
            .SoBeHappy()
            .UnlessItFailed();
        }

        private static async Task<StockClientOutcome> RunExecAsync(OpenSshToolchain toolchain, InteropWorkspace workspace)
        {
            SshServer server = NewServer(workspace);
            server.MapExec(async (context, cancellationToken) =>
            {
                await context.WriteAsync($"interop-exec:{context.CommandLine}", cancellationToken);
                await context.ExitAsync(0, cancellationToken);
            });
            try
            {
                await server.StartAsync(new IPEndPoint(IPAddress.Loopback, 0));
                int port = server.ListenEndPoint!.Port;
                workspace.WriteKnownHosts("127.0.0.1", port);
                OpenSshClientCommand clientCommand = new OpenSshClientCommand(toolchain, workspace);
                SubprocessResult result = clientCommand.Exec("127.0.0.1", port, "echo interop", PinnedAlgorithms);
                return new StockClientOutcome(result);
            }
            finally
            {
                await server.DisposeAsync();
            }
        }

        private static async Task<StockClientRoundTripOutcome> RunSftpRoundTripAsync(OpenSshToolchain toolchain, InteropWorkspace workspace)
        {
            InMemorySftpFileSystem fileSystem = new InMemorySftpFileSystem();
            SshServer server = NewServer(workspace);
            server.MapSftp(fileSystem);
            try
            {
                await server.StartAsync(new IPEndPoint(IPAddress.Loopback, 0));
                int port = server.ListenEndPoint!.Port;
                workspace.WriteKnownHosts("127.0.0.1", port);

                byte[] payload = MakePayload();
                string uploadPath = workspace.WriteScratchFile("sftp-upload.bin", string.Empty);
                File.WriteAllBytes(uploadPath, payload);
                string downloadPath = Path.Combine(workspace.Root, "sftp-download.bin");

                OpenSshClientCommand clientCommand = new OpenSshClientCommand(toolchain, workspace);
                SubprocessResult result = clientCommand.Sftp("127.0.0.1", port, new string[]
                {
                    $"put {ForwardSlash(uploadPath)} /roundtrip.bin",
                    $"get /roundtrip.bin {ForwardSlash(downloadPath)}"
                }, PinnedAlgorithms);

                byte[] downloaded = File.Exists(downloadPath) ? File.ReadAllBytes(downloadPath) : Array.Empty<byte>();
                return new StockClientRoundTripOutcome(result, payload, downloaded);
            }
            finally
            {
                await server.DisposeAsync();
            }
        }

        private static async Task<StockClientScpOutcome> RunScpRoundTripAsync(OpenSshToolchain toolchain, InteropWorkspace workspace)
        {
            InMemorySftpFileSystem fileSystem = new InMemorySftpFileSystem();
            SshServer server = NewServer(workspace);
            // Stock scp uses the SFTP protocol from OpenSSH 9.0 and the legacy exec-based protocol before that —
            // map both so either transport lands on the same store.
            server.MapSftp(fileSystem);
            server.MapScp(fileSystem);
            try
            {
                await server.StartAsync(new IPEndPoint(IPAddress.Loopback, 0));
                int port = server.ListenEndPoint!.Port;
                workspace.WriteKnownHosts("127.0.0.1", port);

                byte[] payload = MakePayload();
                string uploadPath = Path.Combine(workspace.Root, "scp-upload.bin");
                File.WriteAllBytes(uploadPath, payload);
                string downloadPath = Path.Combine(workspace.Root, "scp-download.bin");

                OpenSshClientCommand clientCommand = new OpenSshClientCommand(toolchain, workspace);
                SubprocessResult uploadResult = clientCommand.Scp(port, ForwardSlash(uploadPath), clientCommand.RemoteSpec("127.0.0.1", "/scp-roundtrip.bin"), PinnedAlgorithms);
                SubprocessResult downloadResult = clientCommand.Scp(port, clientCommand.RemoteSpec("127.0.0.1", "/scp-roundtrip.bin"), ForwardSlash(downloadPath), PinnedAlgorithms);

                byte[] downloaded = File.Exists(downloadPath) ? File.ReadAllBytes(downloadPath) : Array.Empty<byte>();
                return new StockClientScpOutcome(uploadResult, downloadResult, payload, downloaded);
            }
            finally
            {
                await server.DisposeAsync();
            }
        }

        /// <summary>
        /// Builds our production server trusting the workspace's minted keys: host key loaded through
        /// SshPrivateKeyReader (real ssh-keygen output exercises the reader for free) and publickey auth
        /// authorizing the minted user key's blob.
        /// </summary>
        private static SshServer NewServer(InteropWorkspace workspace)
        {
            SshServer server = new SshServer();
            ISshPrivateKey hostKey = SshPrivateKeyReader.Read(workspace.HostKeyText);
            ISshPrivateKey userKey = SshPrivateKeyReader.Read(workspace.UserKeyText);
            server.AddHostKey(hostKey);
            server.UsePublicKeyAuthentication(new FixedPublicKeyAuthenticator(userKey.PublicKeyBlob));
            return server;
        }

        private static byte[] MakePayload()
        {
            byte[] payload = new byte[64 * 1024 + 17];
            for (int i = 0; i < payload.Length; i++)
            {
                payload[i] = (byte)(i % 251);
            }
            return payload;
        }

        private static string ForwardSlash(string path)
        {
            return path.Replace('\\', '/');
        }

        private sealed record StockClientOutcome(SubprocessResult Result);

        private sealed record StockClientRoundTripOutcome(SubprocessResult Result, byte[] UploadedBytes, byte[] DownloadedBytes);

        private sealed record StockClientScpOutcome(SubprocessResult UploadResult, SubprocessResult DownloadResult, byte[] UploadedBytes, byte[] DownloadedBytes);
    }
}
