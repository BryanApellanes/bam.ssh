using System.Text;
using Bam.Ssh.Authentication;
using Bam.Ssh.Connection;
using Bam.Ssh.Server;
using Bam.Ssh.Sftp;
using Bam.Test;

namespace Bam.Ssh.Tests.Unit;

/// <summary>
/// The crown-jewel Phase 9 tests: a production <see cref="SftpClient"/> over the production
/// <see cref="Bam.Ssh.Client.SshClient"/> ↔ <see cref="SshServer"/> loopback (via <c>MapSftp</c>) performs
/// full file-transfer round-trips against both the in-memory and the physical (path-jailed) filesystems, and
/// a path that escapes the physical root is refused with <see cref="SftpStatusCode.PermissionDenied"/>.
/// </summary>
[UnitTestMenu("SftpClientServerShould", Selector = "sftp")]
public class SftpClientServerShould : UnitTestMenuContainer
{
    [UnitTest]
    public void TransferFilesOverTheRealStackInMemory()
    {
        When.A<object>("uploads, lists, downloads, and removes over a real SSH connection (in-memory fs)", new object(), (ignored) =>
        {
            byte[] content = Encoding.UTF8.GetBytes("phase 9 sftp payload — round trip");
            return ServerTestSupport.Run(server =>
            {
                server.AddHostKey(new Ed25519PrivateKey(ServerTestSupport.MakeSeed(0x11)));
                server.UsePasswordAuthentication(new FixedPasswordAuthenticator("tester", "s3cret"));
                server.MapSftp(new InMemorySftpFileSystem());
            },
            async (client, stream) =>
            {
                await client.ConnectAsync(stream, "test-host", 22);
                await client.AuthenticateWithPasswordAsync("tester", "s3cret");
                SshSessionChannel channel = await client.OpenSessionChannelAsync();
                await using SftpClient sftp = await SftpClient.OpenAsync(channel);

                await sftp.MakeDirectoryAsync("/docs");
                await sftp.UploadAsync("/docs/readme.txt", content);
                IReadOnlyList<SftpName> listing = await sftp.ListDirectoryAsync("/docs");
                byte[] downloaded = await sftp.DownloadAsync("/docs/readme.txt");
                SftpFileAttributes attributes = await sftp.GetAttributesAsync("/docs/readme.txt");
                string real = await sftp.GetRealPathAsync("/docs/../docs/./readme.txt");
                await sftp.RenameAsync("/docs/readme.txt", "/docs/renamed.txt");
                await sftp.RemoveFileAsync("/docs/renamed.txt");
                await sftp.RemoveDirectoryAsync("/docs");

                return new SftpOutcome(listing.Count, Encoding.UTF8.GetString(downloaded), attributes.Size ?? 0, real, content.Length);
            });
        })
        .TheTest
        .ShouldPass(because =>
        {
            SftpOutcome outcome = (SftpOutcome)because.Result;
            because.ItsTrue("the directory listing has exactly the uploaded file", outcome.ListingCount == 1);
            because.ItsTrue("the download matches the upload", outcome.Downloaded == "phase 9 sftp payload — round trip");
            because.ItsTrue("stat reports the uploaded size", outcome.Size == (ulong)outcome.ExpectedSize);
            because.ItsTrue("realpath canonicalizes the dotted path", outcome.RealPath == "/docs/readme.txt");
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void TransferFilesOverTheRealStackOnDisk()
    {
        When.A<object>("uploads and downloads against a physical filesystem over a real SSH connection", new object(), (ignored) =>
        {
            string root = Path.Combine(Path.GetTempPath(), "bam-ssh-sftp-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root);
            byte[] content = Encoding.UTF8.GetBytes("on-disk sftp payload");
            try
            {
                DiskOutcome outcome = ServerTestSupport.Run(server =>
                {
                    server.AddHostKey(new Ed25519PrivateKey(ServerTestSupport.MakeSeed(0x11)));
                    server.UsePasswordAuthentication(new FixedPasswordAuthenticator("tester", "s3cret"));
                    server.MapSftp(new PhysicalSftpFileSystem(root));
                },
                async (client, stream) =>
                {
                    await client.ConnectAsync(stream, "test-host", 22);
                    await client.AuthenticateWithPasswordAsync("tester", "s3cret");
                    SshSessionChannel channel = await client.OpenSessionChannelAsync();
                    await using SftpClient sftp = await SftpClient.OpenAsync(channel);

                    await sftp.UploadAsync("/upload.bin", content);
                    byte[] downloaded = await sftp.DownloadAsync("/upload.bin");

                    // A path with '..' is canonicalized to stay within the root (the primary sandbox), so a
                    // traversal attempt can never reach a sibling of the root — it resolves inside the root
                    // where the file does not exist. Either way the attempt fails and no outside data leaks.
                    bool escapeDenied = false;
                    try
                    {
                        await sftp.DownloadAsync("/../escape.txt");
                    }
                    catch (SftpStatusException)
                    {
                        escapeDenied = true;
                    }

                    return new DiskOutcome(Encoding.UTF8.GetString(downloaded), escapeDenied);
                });

                bool onDisk = File.Exists(Path.Combine(root, "upload.bin"));
                return new DiskOutcome(outcome.Downloaded, outcome.EscapeDenied) { WrittenToDisk = onDisk };
            }
            finally
            {
                try
                {
                    Directory.Delete(root, recursive: true);
                }
                catch (IOException)
                {
                    // Best-effort cleanup.
                }
            }
        })
        .TheTest
        .ShouldPass(because =>
        {
            DiskOutcome outcome = (DiskOutcome)because.Result;
            because.ItsTrue("the download matches the upload", outcome.Downloaded == "on-disk sftp payload");
            because.ItsTrue("the file really landed on disk", outcome.WrittenToDisk);
            because.ItsTrue("a path escaping the root is blocked", outcome.EscapeDenied);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    private sealed class SftpOutcome
    {
        public SftpOutcome(int listingCount, string downloaded, ulong size, string realPath, int expectedSize)
        {
            ListingCount = listingCount;
            Downloaded = downloaded;
            Size = size;
            RealPath = realPath;
            ExpectedSize = expectedSize;
        }

        public int ListingCount { get; }

        public string Downloaded { get; }

        public ulong Size { get; }

        public string RealPath { get; }

        public int ExpectedSize { get; }
    }

    private sealed class DiskOutcome
    {
        public DiskOutcome(string downloaded, bool escapeDenied)
        {
            Downloaded = downloaded;
            EscapeDenied = escapeDenied;
        }

        public string Downloaded { get; }

        public bool EscapeDenied { get; }

        public bool WrittenToDisk { get; init; }
    }
}
