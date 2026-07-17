using Bam.Ssh.Scp;
using Bam.Test;

namespace Bam.Ssh.Tests.Unit;

/// <summary>
/// Unit tests for the SCP protocol primitives that need no channel: control-record parsing and formatting
/// (<c>C</c>/<c>D</c>/<c>E</c>/<c>T</c>) and <c>scp</c> command-line parsing (mode flags, bundled flags,
/// quoted paths, and rejection of malformed lines).
/// </summary>
[UnitTestMenu("ScpProtocolShould", Selector = "scp-proto")]
public class ScpProtocolShould : UnitTestMenuContainer
{
    [UnitTest]
    public void ParseAndFormatControlRecords()
    {
        When.A<object>("round-trips C, D, E, and T control records through format and parse", new object(), (ignored) =>
        {
            ScpControlMessage file = ScpControlMessage.Parse(ScpControlMessage.FormatFile(0x1A4, 42, "report.txt"));
            ScpControlMessage directory = ScpControlMessage.Parse(ScpControlMessage.FormatDirectory(0x1ED, "sub dir"));
            ScpControlMessage endDirectory = ScpControlMessage.Parse(ScpControlMessage.EndDirectoryLine);
            ScpControlMessage time = ScpControlMessage.Parse(ScpControlMessage.FormatTime(1700000000, 1700000001));

            bool malformedRejected = false;
            try
            {
                ScpControlMessage.Parse("Znope");
            }
            catch (ScpException)
            {
                malformedRejected = true;
            }

            return new ControlOutcome(file, directory, endDirectory, time, malformedRejected);
        })
        .TheTest
        .ShouldPass(because =>
        {
            ControlOutcome outcome = (ControlOutcome)because.Result;
            because.ItsTrue("a C record parses type, octal mode, size, and name", outcome.File.Type == ScpControlType.File && outcome.File.Mode == 0x1A4 && outcome.File.Size == 42 && outcome.File.Name == "report.txt");
            because.ItsTrue("a D record parses type, mode, and a name with a space", outcome.Directory.Type == ScpControlType.Directory && outcome.Directory.Mode == 0x1ED && outcome.Directory.Name == "sub dir");
            because.ItsTrue("an E record parses as end-of-directory", outcome.EndDirectory.Type == ScpControlType.EndDirectory);
            because.ItsTrue("a T record parses modify and access times", outcome.Time.Type == ScpControlType.Time && outcome.Time.ModifyTime == 1700000000 && outcome.Time.AccessTime == 1700000001);
            because.ItsTrue("an unknown record byte is rejected", outcome.MalformedRejected);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void ParseScpCommandLines()
    {
        When.A<object>("parses sink, source, bundled, and quoted scp command lines and rejects bad ones", new object(), (ignored) =>
        {
            ScpCommand sink = ScpCommand.Parse("scp -t /var/incoming");
            ScpCommand source = ScpCommand.Parse("scp -f /home/me/file.txt");
            ScpCommand bundled = ScpCommand.Parse("scp -rt /data");
            ScpCommand preserved = ScpCommand.Parse("scp -p -r -t \"/a b/c\"");
            ScpCommand qualified = ScpCommand.Parse("/usr/bin/scp -f '/quoted path.txt'");

            bool isScp = ScpCommand.IsScpCommand("scp -t /x");
            bool notScp = ScpCommand.IsScpCommand("ls -l");

            bool noModeRejected = false;
            try
            {
                ScpCommand.Parse("scp /just/a/path");
            }
            catch (ScpException)
            {
                noModeRejected = true;
            }

            return new CommandOutcome(sink, source, bundled, preserved, qualified, isScp, notScp, noModeRejected);
        })
        .TheTest
        .ShouldPass(because =>
        {
            CommandOutcome outcome = (CommandOutcome)because.Result;
            because.ItsTrue("-t is a sink transfer to the given path", outcome.Sink.Mode == ScpTransferMode.Sink && outcome.Sink.Path == "/var/incoming");
            because.ItsTrue("-f is a source transfer from the given path", outcome.Source.Mode == ScpTransferMode.Source && outcome.Source.Path == "/home/me/file.txt");
            because.ItsTrue("bundled -rt sets recursive and sink", outcome.Bundled.Recursive && outcome.Bundled.Mode == ScpTransferMode.Sink);
            because.ItsTrue("-p -r -t sets preserve-times, recursive, and a quoted path", outcome.Preserved.PreserveTimes && outcome.Preserved.Recursive && outcome.Preserved.Path == "/a b/c");
            because.ItsTrue("a path-qualified scp with a single-quoted path parses", outcome.Qualified.Mode == ScpTransferMode.Source && outcome.Qualified.Path == "/quoted path.txt");
            because.ItsTrue("IsScpCommand recognizes scp and rejects non-scp", outcome.IsScp && !outcome.NotScp);
            because.ItsTrue("a command with neither -t nor -f is rejected", outcome.NoModeRejected);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    private sealed class ControlOutcome
    {
        public ControlOutcome(ScpControlMessage file, ScpControlMessage directory, ScpControlMessage endDirectory, ScpControlMessage time, bool malformedRejected)
        {
            File = file;
            Directory = directory;
            EndDirectory = endDirectory;
            Time = time;
            MalformedRejected = malformedRejected;
        }

        public ScpControlMessage File { get; }

        public ScpControlMessage Directory { get; }

        public ScpControlMessage EndDirectory { get; }

        public ScpControlMessage Time { get; }

        public bool MalformedRejected { get; }
    }

    private sealed class CommandOutcome
    {
        public CommandOutcome(ScpCommand sink, ScpCommand source, ScpCommand bundled, ScpCommand preserved, ScpCommand qualified, bool isScp, bool notScp, bool noModeRejected)
        {
            Sink = sink;
            Source = source;
            Bundled = bundled;
            Preserved = preserved;
            Qualified = qualified;
            IsScp = isScp;
            NotScp = notScp;
            NoModeRejected = noModeRejected;
        }

        public ScpCommand Sink { get; }

        public ScpCommand Source { get; }

        public ScpCommand Bundled { get; }

        public ScpCommand Preserved { get; }

        public ScpCommand Qualified { get; }

        public bool IsScp { get; }

        public bool NotScp { get; }

        public bool NoModeRejected { get; }
    }
}
