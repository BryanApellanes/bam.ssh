using System.Text;
using Bam.Ssh.Transport;
using Bam.Test;

namespace Bam.Ssh.Tests.Unit;

[UnitTestMenu("SshIdentificationStringShould", Selector = "sid")]
public class SshIdentificationStringShould : UnitTestMenuContainer
{
    [UnitTest]
    public void ParseAndFormatRoundTrip()
    {
        When.A<object>("parses and reformats identification lines",
            new object(),
            (ignored) =>
            {
                bool[] results = new bool[6];

                results[0] = SshIdentificationString.TryParse("SSH-2.0-OpenSSH_9.6", out SshIdentificationString openssh);
                results[1] = openssh.ProtocolVersion == "2.0" && openssh.SoftwareVersion == "OpenSSH_9.6" && openssh.Comments is null;
                results[2] = openssh.ToString() == "SSH-2.0-OpenSSH_9.6";

                results[3] = SshIdentificationString.TryParse("SSH-2.0-Bam.Ssh_1.0 a comment here", out SshIdentificationString withComments);
                results[4] = withComments.Comments == "a comment here" && withComments.ToString() == "SSH-2.0-Bam.Ssh_1.0 a comment here";

                SshIdentificationString built = new SshIdentificationString("2.0", "Bam.Ssh_1.0");
                results[5] = Encoding.ASCII.GetString(built.ToWireBytes()) == "SSH-2.0-Bam.Ssh_1.0\r\n";

                return results;
            })
        .TheTest
        .ShouldPass(because =>
        {
            bool[] results = (bool[])because.Result;
            because.ItsTrue("the OpenSSH example parses", results[0]);
            because.ItsTrue("its fields are correct", results[1]);
            because.ItsTrue("it reformats identically", results[2]);
            because.ItsTrue("a line with comments parses", results[3]);
            because.ItsTrue("comments round-trip", results[4]);
            because.ItsTrue("wire bytes carry the trailing CRLF", results[5]);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RejectMalformedIdentifications()
    {
        When.A<object>("rejects lines that are not valid identification strings",
            new object(),
            (ignored) =>
            {
                bool[] results = new bool[5];
                results[0] = !SshIdentificationString.TryParse("GET / HTTP/1.1", out SshIdentificationString _);
                results[1] = !SshIdentificationString.TryParse("SSH-2.0-", out SshIdentificationString _);
                results[2] = !SshIdentificationString.TryParse("SSH-2.0", out SshIdentificationString _);
                results[3] = !SshIdentificationString.TryParse("", out SshIdentificationString _);
                bool threwOnBadSoftware;
                try
                {
                    SshIdentificationString bad = new SshIdentificationString("2.0", "has space");
                    threwOnBadSoftware = false;
                }
                catch (ArgumentException)
                {
                    threwOnBadSoftware = true;
                }
                results[4] = threwOnBadSoftware;
                return results;
            })
        .TheTest
        .ShouldPass(because =>
        {
            bool[] results = (bool[])because.Result;
            because.ItsTrue("a non-SSH line is rejected", results[0]);
            because.ItsTrue("an empty software version is rejected", results[1]);
            because.ItsTrue("a line with no second hyphen is rejected", results[2]);
            because.ItsTrue("an empty line is rejected", results[3]);
            because.ItsTrue("a software version with a space is rejected at construction", results[4]);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RecognizeSupportedProtocolVersions()
    {
        When.A<object>("accepts 2.0 and 1.99 and rejects 1.5",
            new object(),
            (ignored) =>
            {
                SshIdentificationString.TryParse("SSH-2.0-X", out SshIdentificationString twoZero);
                SshIdentificationString.TryParse("SSH-1.99-X", out SshIdentificationString oneNineNine);
                SshIdentificationString.TryParse("SSH-1.5-X", out SshIdentificationString oneFive);
                return new bool[] { twoZero.IsProtocolSupported, oneNineNine.IsProtocolSupported, oneFive.IsProtocolSupported };
            })
        .TheTest
        .ShouldPass(because =>
        {
            bool[] results = (bool[])because.Result;
            because.ItsTrue("2.0 is supported", results[0]);
            because.ItsTrue("1.99 is supported", results[1]);
            because.ItsTrue("1.5 is not supported", !results[2]);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }
}
