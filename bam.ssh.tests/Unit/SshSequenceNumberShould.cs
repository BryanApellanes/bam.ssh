using Bam.Test;

namespace Bam.Ssh.Tests.Unit;

[UnitTestMenu("SshSequenceNumberShould", Selector = "ssn")]
public class SshSequenceNumberShould : UnitTestMenuContainer
{
    [UnitTest]
    public void StartAtZeroAndAdvanceSequentially()
    {
        When.A<object>("returns the current number and then increments",
            new object(),
            (ignored) =>
            {
                SshSequenceNumber sequence = new SshSequenceNumber();
                uint first = sequence.Advance();
                uint second = sequence.Advance();
                uint third = sequence.Advance();
                return new uint[] { first, second, third, sequence.Value };
            })
        .TheTest
        .ShouldPass(because =>
        {
            uint[] results = (uint[])because.Result;
            because.ItsTrue("the first packet uses sequence number 0", results[0] == 0);
            because.ItsTrue("the second packet uses sequence number 1", results[1] == 1);
            because.ItsTrue("the third packet uses sequence number 2", results[2] == 2);
            because.ItsTrue("the next packet will use sequence number 3", results[3] == 3);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void WrapToZeroAfterUIntMax()
    {
        When.A<object>("wraps to zero after 2^32 - 1 per RFC 4253 section 6.4",
            new object(),
            (ignored) =>
            {
                SshSequenceNumber sequence = new SshSequenceNumber(uint.MaxValue);
                uint atMax = sequence.Advance();
                uint afterWrap = sequence.Advance();
                return new uint[] { atMax, afterWrap };
            })
        .TheTest
        .ShouldPass(because =>
        {
            uint[] results = (uint[])because.Result;
            because.ItsTrue("the packet at the boundary uses uint.MaxValue", results[0] == uint.MaxValue);
            because.ItsTrue("the next packet wraps to sequence number 0", results[1] == 0);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }
}
