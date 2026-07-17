using System.Text;
using Bam.Ssh.Authentication;
using Bam.Ssh.Scp;
using Bam.Ssh.Server;
using Bam.Ssh.Sftp;
using Bam.Test;

namespace Bam.Ssh.Tests.Unit;

/// <summary>
/// The crown-jewel Phase 10 tests: a production <see cref="ScpClient"/> over the production
/// <see cref="Bam.Ssh.Client.SshClient"/> ↔ <see cref="SshServer"/> loopback (via <c>MapScp</c>) performs
/// full SCP round-trips — a single file and a recursive directory tree — against both an in-memory and a
/// physical (path-jailed) filesystem, and a download of a missing remote path is refused with
/// <see cref="ScpException"/>.
/// </summary>
[UnitTestMenu("ScpClientServerShould", Selector = "scp")]
public class ScpClientServerShould : UnitTestMenuContainer
{
    [UnitTest]
    public void TransferFilesOverTheRealStackInMemory()
    {
        When.A<object>("uploads and downloads a file and a directory tree over a real SSH connection (in-memory fs)", new object(), (ignored) =>
        {
            byte[] content = Encoding.UTF8.GetBytes("phase 10 scp payload — round trip");
            byte[] alpha = Encoding.UTF8.GetBytes("alpha-file");
            byte[] beta = Encoding.UTF8.GetBytes("beta-file");

            InMemorySftpFileSystem serverFileSystem = new InMemorySftpFileSystem();
            InMemorySftpFileSystem localFileSystem = new InMemorySftpFileSystem();

            return ServerTestSupport.Run(server =>
            {
                server.AddHostKey(new Ed25519PrivateKey(ServerTestSupport.MakeSeed(0x11)));
                server.UsePasswordAuthentication(new FixedPasswordAuthenticator("tester", "s3cret"));
                server.MapScp(serverFileSystem);
            },
            async (client, stream) =>
            {
                await WriteFileAsync(localFileSystem, "/src.txt", content);
                await MakeDirectoryAsync(localFileSystem, "/tree");
                await WriteFileAsync(localFileSystem, "/tree/a.txt", alpha);
                await MakeDirectoryAsync(localFileSystem, "/tree/sub");
                await WriteFileAsync(localFileSystem, "/tree/sub/b.txt", beta);

                await client.ConnectAsync(stream, "test-host", 22);
                await client.AuthenticateWithPasswordAsync("tester", "s3cret");
                ScpClient scp = new ScpClient(client.Connection);

                // Single file: local -> remote, then remote -> a fresh local path.
                await scp.UploadAsync(localFileSystem, "/src.txt", "/dst.txt");
                await scp.DownloadAsync(localFileSystem, "/dst.txt", "/back.txt");

                // Directory tree: local -> remote (recursive), then remote -> a fresh local tree.
                await scp.UploadAsync(localFileSystem, "/tree", "/rdst", recursive: true);
                await scp.DownloadAsync(localFileSystem, "/rdst", "/rback", recursive: true);

                byte[] serverDst = await ReadFileAsync(serverFileSystem, "/dst.txt");
                byte[] localBack = await ReadFileAsync(localFileSystem, "/back.txt");
                byte[] serverTreeA = await ReadFileAsync(serverFileSystem, "/rdst/a.txt");
                byte[] localTreeA = await ReadFileAsync(localFileSystem, "/rback/a.txt");
                byte[] localTreeB = await ReadFileAsync(localFileSystem, "/rback/sub/b.txt");

                return new ScpOutcome(
                    Encoding.UTF8.GetString(serverDst),
                    Encoding.UTF8.GetString(localBack),
                    Encoding.UTF8.GetString(serverTreeA),
                    Encoding.UTF8.GetString(localTreeA),
                    Encoding.UTF8.GetString(localTreeB));
            });
        })
        .TheTest
        .ShouldPass(because =>
        {
            ScpOutcome outcome = (ScpOutcome)because.Result;
            because.ItsTrue("the uploaded file landed on the server", outcome.ServerFile == "phase 10 scp payload — round trip");
            because.ItsTrue("the downloaded file matches the original", outcome.LocalFile == "phase 10 scp payload — round trip");
            because.ItsTrue("a recursive upload placed the nested file on the server", outcome.ServerTreeA == "alpha-file");
            because.ItsTrue("a recursive download restored the top-level file", outcome.LocalTreeA == "alpha-file");
            because.ItsTrue("a recursive download restored the nested subdirectory file", outcome.LocalTreeB == "beta-file");
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void TransferFilesOverTheRealStackOnDisk()
    {
        When.A<object>("uploads and downloads against a physical filesystem over a real SSH connection", new object(), (ignored) =>
        {
            string clientRoot = Path.Combine(Path.GetTempPath(), "bam-ssh-scp-c-" + Guid.NewGuid().ToString("N"));
            string serverRoot = Path.Combine(Path.GetTempPath(), "bam-ssh-scp-s-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(clientRoot);
            Directory.CreateDirectory(serverRoot);
            byte[] content = Encoding.UTF8.GetBytes("on-disk scp payload");
            File.WriteAllBytes(Path.Combine(clientRoot, "upload.bin"), content);
            try
            {
                DiskOutcome outcome = ServerTestSupport.Run(server =>
                {
                    server.AddHostKey(new Ed25519PrivateKey(ServerTestSupport.MakeSeed(0x11)));
                    server.UsePasswordAuthentication(new FixedPasswordAuthenticator("tester", "s3cret"));
                    server.MapScp(new PhysicalSftpFileSystem(serverRoot));
                },
                async (client, stream) =>
                {
                    await client.ConnectAsync(stream, "test-host", 22);
                    await client.AuthenticateWithPasswordAsync("tester", "s3cret");
                    ScpClient scp = new ScpClient(client.Connection);
                    PhysicalSftpFileSystem localFileSystem = new PhysicalSftpFileSystem(clientRoot);

                    await scp.UploadAsync(localFileSystem, "/upload.bin", "/landed.bin");
                    await scp.DownloadAsync(localFileSystem, "/landed.bin", "/downloaded.bin");

                    byte[] downloaded = await ReadFileAsync(localFileSystem, "/downloaded.bin");
                    return new DiskOutcome(Encoding.UTF8.GetString(downloaded), false);
                });

                bool onServerDisk = File.Exists(Path.Combine(serverRoot, "landed.bin"));
                bool onClientDisk = File.Exists(Path.Combine(clientRoot, "downloaded.bin"));
                return new DiskOutcome(outcome.Downloaded, onServerDisk) { DownloadedToDisk = onClientDisk };
            }
            finally
            {
                TryDelete(clientRoot);
                TryDelete(serverRoot);
            }
        })
        .TheTest
        .ShouldPass(because =>
        {
            DiskOutcome outcome = (DiskOutcome)because.Result;
            because.ItsTrue("the download matches the upload", outcome.Downloaded == "on-disk scp payload");
            because.ItsTrue("the uploaded file really landed on the server's disk", outcome.LandedOnServer);
            because.ItsTrue("the downloaded file really landed on the client's disk", outcome.DownloadedToDisk);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RejectDownloadOfMissingRemotePath()
    {
        When.A<object>("surfaces a ScpException when the remote source path does not exist", new object(), (ignored) =>
        {
            InMemorySftpFileSystem serverFileSystem = new InMemorySftpFileSystem();
            InMemorySftpFileSystem localFileSystem = new InMemorySftpFileSystem();

            return ServerTestSupport.Run(server =>
            {
                server.AddHostKey(new Ed25519PrivateKey(ServerTestSupport.MakeSeed(0x11)));
                server.UsePasswordAuthentication(new FixedPasswordAuthenticator("tester", "s3cret"));
                server.MapScp(serverFileSystem);
            },
            async (client, stream) =>
            {
                await client.ConnectAsync(stream, "test-host", 22);
                await client.AuthenticateWithPasswordAsync("tester", "s3cret");
                ScpClient scp = new ScpClient(client.Connection);

                bool refused = false;
                try
                {
                    await scp.DownloadAsync(localFileSystem, "/does-not-exist.bin", "/x.bin");
                }
                catch (ScpException)
                {
                    refused = true;
                }

                return refused;
            });
        })
        .TheTest
        .ShouldPass(because =>
        {
            because.ItsTrue("a download of a missing remote path is refused", (bool)because.Result);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    private static async Task WriteFileAsync(ISftpFileSystem fileSystem, string path, byte[] data)
    {
        SftpFileAttributes attributes = new SftpFileAttributes(permissions: SftpConstants.ModeRegularFile | SftpConstants.DefaultFilePermissions);
        ISftpFileHandle handle = await fileSystem.OpenFileAsync(path, SftpOpenFlags.Create | SftpOpenFlags.Write | SftpOpenFlags.Truncate, attributes);
        try
        {
            await handle.WriteAsync(0, data);
        }
        finally
        {
            await handle.DisposeAsync();
        }
    }

    private static async Task MakeDirectoryAsync(ISftpFileSystem fileSystem, string path)
    {
        SftpFileAttributes attributes = new SftpFileAttributes(permissions: SftpConstants.ModeDirectory | SftpConstants.DefaultDirectoryPermissions);
        await fileSystem.MakeDirectoryAsync(path, attributes);
    }

    private static async Task<byte[]> ReadFileAsync(ISftpFileSystem fileSystem, string path)
    {
        SftpFileAttributes attributes = await fileSystem.GetAttributesAsync(path, followSymbolicLinks: true);
        int size = (int)(attributes.Size ?? 0);
        byte[] buffer = new byte[size];
        ISftpFileHandle handle = await fileSystem.OpenFileAsync(path, SftpOpenFlags.Read, new SftpFileAttributes());
        try
        {
            int offset = 0;
            while (offset < size)
            {
                int read = await handle.ReadAsync((ulong)offset, buffer.AsMemory(offset));
                if (read <= 0)
                {
                    break;
                }

                offset += read;
            }
        }
        finally
        {
            await handle.DisposeAsync();
        }

        return buffer;
    }

    private static void TryDelete(string directory)
    {
        try
        {
            Directory.Delete(directory, recursive: true);
        }
        catch (IOException)
        {
            // Best-effort cleanup.
        }
    }

    private sealed class ScpOutcome
    {
        public ScpOutcome(string serverFile, string localFile, string serverTreeA, string localTreeA, string localTreeB)
        {
            ServerFile = serverFile;
            LocalFile = localFile;
            ServerTreeA = serverTreeA;
            LocalTreeA = localTreeA;
            LocalTreeB = localTreeB;
        }

        public string ServerFile { get; }

        public string LocalFile { get; }

        public string ServerTreeA { get; }

        public string LocalTreeA { get; }

        public string LocalTreeB { get; }
    }

    private sealed class DiskOutcome
    {
        public DiskOutcome(string downloaded, bool landedOnServer)
        {
            Downloaded = downloaded;
            LandedOnServer = landedOnServer;
        }

        public string Downloaded { get; }

        public bool LandedOnServer { get; }

        public bool DownloadedToDisk { get; init; }
    }
}
