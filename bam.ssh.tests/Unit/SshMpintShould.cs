using System.Buffers;
using Bam.Test;

namespace Bam.Ssh.Tests.Unit;

[UnitTestMenu("SshMpintShould", Selector = "smp")]
public class SshMpintShould : UnitTestMenuContainer
{
    [UnitTest]
    public void NormalizeMagnitudes()
    {
        When.A<ArrayBufferWriter<byte>>("strips leading zeros and computes body lengths",
            new ArrayBufferWriter<byte>(),
            (output) =>
            {
                bool[] results = new bool[6];
                results[0] = SshMpint.StripLeadingZeros(TestBytes.FromHex("000001")).SequenceEqual(TestBytes.FromHex("01"));
                results[1] = SshMpint.StripLeadingZeros(TestBytes.FromHex("0000")).IsEmpty;
                results[2] = SshMpint.GetUnsignedBodyLength(ReadOnlySpan<byte>.Empty) == 0;
                results[3] = SshMpint.GetUnsignedBodyLength(TestBytes.FromHex("7f")) == 1;
                results[4] = SshMpint.GetUnsignedBodyLength(TestBytes.FromHex("80")) == 2;
                results[5] = SshMpint.GetUnsignedBodyLength(TestBytes.FromHex("0080")) == 2;
                return results;
            })
        .TheTest
        .ShouldPass(because =>
        {
            bool[] results = (bool[])because.Result;
            because.ItsTrue("leading zeros are stripped", results[0]);
            because.ItsTrue("all-zero magnitude strips to empty", results[1]);
            because.ItsTrue("zero has body length 0", results[2]);
            because.ItsTrue("7f has body length 1", results[3]);
            because.ItsTrue("80 has body length 2 (sign byte added)", results[4]);
            because.ItsTrue("0080 normalizes to body length 2", results[5]);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void EnforceMinimalEncodingAndSign()
    {
        When.A<ArrayBufferWriter<byte>>("validates minimal encodings and rejects negatives",
            new ArrayBufferWriter<byte>(),
            (output) =>
            {
                bool[] results = new bool[7];
                results[0] = !ThrowsWireFormat(() => SshMpint.ValidateMinimalEncoding(ReadOnlySpan<byte>.Empty));
                results[1] = !ThrowsWireFormat(() => SshMpint.ValidateMinimalEncoding(TestBytes.FromHex("0080")));
                results[2] = !ThrowsWireFormat(() => SshMpint.ValidateMinimalEncoding(TestBytes.FromHex("ff7f")));
                results[3] = ThrowsWireFormat(() => SshMpint.ValidateMinimalEncoding(TestBytes.FromHex("007f")));
                results[4] = ThrowsWireFormat(() => SshMpint.ValidateMinimalEncoding(TestBytes.FromHex("00")));
                results[5] = ThrowsWireFormat(() => SshMpint.ToUnsignedMagnitude(TestBytes.FromHex("80")));
                results[6] = SshMpint.ToUnsignedMagnitude(TestBytes.FromHex("0080")).SequenceEqual(TestBytes.FromHex("80"));
                return results;
            })
        .TheTest
        .ShouldPass(because =>
        {
            bool[] results = (bool[])because.Result;
            because.ItsTrue("empty body (zero) is valid", results[0]);
            because.ItsTrue("necessary sign byte 00 80 is valid", results[1]);
            because.ItsTrue("minimal negative ff 7f is valid", results[2]);
            because.ItsTrue("unnecessary 00 before low byte is rejected", results[3]);
            because.ItsTrue("lone 00 (non-minimal zero) is rejected", results[4]);
            because.ItsTrue("negative body is rejected as magnitude", results[5]);
            because.ItsTrue("sign byte is stripped from magnitude", results[6]);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    private static bool ThrowsWireFormat(Action action)
    {
        try
        {
            action();
            return false;
        }
        catch (SshWireFormatException)
        {
            return true;
        }
    }
}
