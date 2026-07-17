using System.Text;
using Bam.Ssh.Sftp;
using Bam.Test;

namespace Bam.Ssh.Tests.Unit;

/// <summary>
/// Unit tests for the SFTP protocol primitives that need no channel: path canonicalization, the ATTRS
/// codec round-trip, and the in-memory virtual filesystem's file/directory operations and error mapping.
/// </summary>
[UnitTestMenu("SftpProtocolShould", Selector = "sftp-proto")]
public class SftpProtocolShould : UnitTestMenuContainer
{
    [UnitTest]
    public void CanonicalizePaths()
    {
        When.A<object>("canonicalizes '.', '..', and duplicate separators", new object(), (ignored) =>
        {
            PathOutcome outcome = new PathOutcome(
                SftpPath.Canonicalize("/a/b/../c"),
                SftpPath.Canonicalize("."),
                SftpPath.Canonicalize("/a//b/"),
                SftpPath.GetParent("/a/b/c"),
                SftpPath.GetFileName("/a/b/c"));
            return outcome;
        })
        .TheTest
        .ShouldPass(because =>
        {
            PathOutcome outcome = (PathOutcome)because.Result;
            because.ItsTrue("'..' pops a segment", outcome.DotDot == "/a/c");
            because.ItsTrue("'.' canonicalizes to root", outcome.Dot == "/");
            because.ItsTrue("duplicate and trailing separators collapse", outcome.Duplicates == "/a/b");
            because.ItsTrue("parent drops the last segment", outcome.Parent == "/a/b");
            because.ItsTrue("file name is the last segment", outcome.FileName == "c");
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RoundTripAttributes()
    {
        When.A<object>("round-trips an ATTRS structure through the wire", new object(), (ignored) =>
        {
            SftpFileAttributes original = new SftpFileAttributes(size: 1234, permissions: SftpConstants.ModeRegularFile | 0x1A4);
            byte[] encoded;
            using (PooledBufferWriter writer = new PooledBufferWriter(32))
            {
                SshWireWriter wire = new SshWireWriter(writer);
                original.WriteTo(ref wire);
                encoded = writer.WrittenSpan.ToArray();
            }
            SshWireReader reader = new SshWireReader(encoded);
            SftpFileAttributes decoded = SftpFileAttributes.ReadFrom(ref reader);
            return decoded;
        })
        .TheTest
        .ShouldPass(because =>
        {
            SftpFileAttributes decoded = (SftpFileAttributes)because.Result;
            because.ItsTrue("size survives the round-trip", decoded.Size == 1234);
            because.ItsTrue("permissions survive the round-trip", decoded.Permissions == (SftpConstants.ModeRegularFile | 0x1A4));
            because.ItsTrue("the regular-file bit is not a directory", !decoded.IsDirectory);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void ServeFileOperationsInMemory()
    {
        When.A<object>("creates, writes, reads, lists, and removes through the in-memory filesystem", new object(), (ignored) =>
        {
            InMemorySftpFileSystem fileSystem = new InMemorySftpFileSystem();
            fileSystem.MakeDirectoryAsync("/data", new SftpFileAttributes()).AsTask().GetAwaiter().GetResult();

            ISftpFileHandle handle = fileSystem.OpenFileAsync("/data/greeting.txt", SftpOpenFlags.Write | SftpOpenFlags.Create, new SftpFileAttributes()).AsTask().GetAwaiter().GetResult();
            byte[] payload = Encoding.UTF8.GetBytes("hello sftp");
            handle.WriteAsync(0, payload).AsTask().GetAwaiter().GetResult();
            handle.DisposeAsync().AsTask().GetAwaiter().GetResult();

            ISftpFileHandle readHandle = fileSystem.OpenFileAsync("/data/greeting.txt", SftpOpenFlags.Read, new SftpFileAttributes()).AsTask().GetAwaiter().GetResult();
            byte[] buffer = new byte[64];
            int read = readHandle.ReadAsync(0, buffer).AsTask().GetAwaiter().GetResult();
            readHandle.DisposeAsync().AsTask().GetAwaiter().GetResult();

            SftpFileAttributes attributes = fileSystem.GetAttributesAsync("/data/greeting.txt", true).AsTask().GetAwaiter().GetResult();

            ISftpDirectoryHandle dir = fileSystem.OpenDirectoryAsync("/data").AsTask().GetAwaiter().GetResult();
            IReadOnlyList<SftpName> entries = dir.ReadAsync().AsTask().GetAwaiter().GetResult();
            dir.DisposeAsync().AsTask().GetAwaiter().GetResult();
            bool listed = false;
            foreach (SftpName entry in entries)
            {
                if (entry.FileName == "greeting.txt")
                {
                    listed = true;
                }
            }

            fileSystem.RenameAsync("/data/greeting.txt", "/data/renamed.txt").AsTask().GetAwaiter().GetResult();
            fileSystem.RemoveFileAsync("/data/renamed.txt").AsTask().GetAwaiter().GetResult();
            fileSystem.RemoveDirectoryAsync("/data").AsTask().GetAwaiter().GetResult();

            bool missingMapped = false;
            try
            {
                fileSystem.GetAttributesAsync("/data", true).AsTask().GetAwaiter().GetResult();
            }
            catch (SftpStatusException exception)
            {
                missingMapped = exception.StatusCode == SftpStatusCode.NoSuchFile;
            }

            return new FileSystemOutcome(Encoding.UTF8.GetString(buffer, 0, read), attributes.Size ?? 0, listed, missingMapped);
        })
        .TheTest
        .ShouldPass(because =>
        {
            FileSystemOutcome outcome = (FileSystemOutcome)because.Result;
            because.ItsTrue("the written bytes read back", outcome.Content == "hello sftp");
            because.ItsTrue("stat reports the written size", outcome.Size == 10);
            because.ItsTrue("the directory listing includes the file", outcome.Listed);
            because.ItsTrue("a removed path maps to NoSuchFile", outcome.MissingMapped);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    private sealed class PathOutcome
    {
        public PathOutcome(string dotDot, string dot, string duplicates, string parent, string fileName)
        {
            DotDot = dotDot;
            Dot = dot;
            Duplicates = duplicates;
            Parent = parent;
            FileName = fileName;
        }

        public string DotDot { get; }

        public string Dot { get; }

        public string Duplicates { get; }

        public string Parent { get; }

        public string FileName { get; }
    }

    private sealed class FileSystemOutcome
    {
        public FileSystemOutcome(string content, ulong size, bool listed, bool missingMapped)
        {
            Content = content;
            Size = size;
            Listed = listed;
            MissingMapped = missingMapped;
        }

        public string Content { get; }

        public ulong Size { get; }

        public bool Listed { get; }

        public bool MissingMapped { get; }
    }
}
