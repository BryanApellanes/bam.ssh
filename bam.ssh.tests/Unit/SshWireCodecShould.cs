using System.Buffers;
using Bam.Test;

namespace Bam.Ssh.Tests.Unit;

[UnitTestMenu("SshWireCodecShould", Selector = "swc")]
public class SshWireCodecShould : UnitTestMenuContainer
{
    [UnitTest]
    public void RoundTripFixedWidthPrimitives()
    {
        When.A<ArrayBufferWriter<byte>>("round-trips byte, boolean, uint32, uint64",
            new ArrayBufferWriter<byte>(),
            (output) =>
            {
                SshWireWriter writer = new SshWireWriter(output);
                writer.WriteByte(0x7E);
                writer.WriteBoolean(true);
                writer.WriteBoolean(false);
                writer.WriteUInt32(0xDEADBEEF);
                writer.WriteUInt64(0x0123456789ABCDEF);

                SshWireReader reader = new SshWireReader(output.WrittenSpan);
                bool[] results = new bool[6];
                results[0] = reader.ReadByte() == 0x7E;
                results[1] = reader.ReadBoolean();
                results[2] = !reader.ReadBoolean();
                results[3] = reader.ReadUInt32() == 0xDEADBEEF;
                results[4] = reader.ReadUInt64() == 0x0123456789ABCDEF;
                results[5] = reader.Remaining == 0;
                return results;
            })
        .TheTest
        .ShouldPass(because =>
        {
            bool[] results = (bool[])because.Result;
            because.ItsTrue("byte round-trips", results[0]);
            because.ItsTrue("true round-trips", results[1]);
            because.ItsTrue("false round-trips", results[2]);
            because.ItsTrue("uint32 round-trips big-endian", results[3]);
            because.ItsTrue("uint64 round-trips big-endian", results[4]);
            because.ItsTrue("no bytes remain", results[5]);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RoundTripStringAndText()
    {
        When.A<ArrayBufferWriter<byte>>("round-trips binary strings and UTF-8 text",
            new ArrayBufferWriter<byte>(),
            (output) =>
            {
                byte[] binary = new byte[] { 0x00, 0xFF, 0x10, 0x20 };
                string text = "héllo, wörld";

                SshWireWriter writer = new SshWireWriter(output);
                writer.WriteString(binary);
                writer.WriteText(text);
                writer.WriteString(ReadOnlySpan<byte>.Empty);

                SshWireReader reader = new SshWireReader(output.WrittenSpan);
                bool[] results = new bool[4];
                results[0] = reader.ReadString().SequenceEqual(binary);
                results[1] = reader.ReadText() == text;
                results[2] = reader.ReadString().IsEmpty;
                results[3] = reader.Remaining == 0;
                return results;
            })
        .TheTest
        .ShouldPass(because =>
        {
            bool[] results = (bool[])because.Result;
            because.ItsTrue("binary string round-trips", results[0]);
            because.ItsTrue("UTF-8 text round-trips", results[1]);
            because.ItsTrue("empty string round-trips", results[2]);
            because.ItsTrue("no bytes remain", results[3]);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RoundTripNameLists()
    {
        When.A<ArrayBufferWriter<byte>>("round-trips RFC 4251 name-list vectors",
            new ArrayBufferWriter<byte>(),
            (output) =>
            {
                SshNameList empty = SshNameList.Empty;
                SshNameList single = new SshNameList("zlib");
                SshNameList multi = new SshNameList("zlib", "none");

                SshWireWriter writer = new SshWireWriter(output);
                writer.WriteNameList(empty);
                writer.WriteNameList(single);
                writer.WriteNameList(multi);

                SshWireReader reader = new SshWireReader(output.WrittenSpan);
                bool[] results = new bool[5];
                results[0] = reader.ReadNameList() == empty;
                results[1] = reader.ReadNameList() == single;
                SshNameList multiBack = reader.ReadNameList();
                results[2] = multiBack == multi;
                results[3] = multiBack.ToString() == "zlib,none";
                results[4] = multiBack.Contains("none") && !multiBack.Contains("nonesuch");
                return results;
            })
        .TheTest
        .ShouldPass(because =>
        {
            bool[] results = (bool[])because.Result;
            because.ItsTrue("empty name-list round-trips", results[0]);
            because.ItsTrue("single name round-trips", results[1]);
            because.ItsTrue("multi name round-trips in order", results[2]);
            because.ItsTrue("comma form matches the RFC example", results[3]);
            because.ItsTrue("containment is exact-match ordinal", results[4]);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void EncodeMpintPerRfcWorkedExamples()
    {
        When.A<ArrayBufferWriter<byte>>("encodes the RFC 4251 §5 mpint vectors",
            new ArrayBufferWriter<byte>(),
            (output) =>
            {
                bool[] results = new bool[3];

                ArrayBufferWriter<byte> zeroOut = new ArrayBufferWriter<byte>();
                SshWireWriter zeroWriter = new SshWireWriter(zeroOut);
                zeroWriter.WriteMultiPrecisionInteger(ReadOnlySpan<byte>.Empty);
                results[0] = zeroOut.WrittenSpan.SequenceEqual(TestBytes.FromHex("00000000"));

                ArrayBufferWriter<byte> bigOut = new ArrayBufferWriter<byte>();
                SshWireWriter bigWriter = new SshWireWriter(bigOut);
                bigWriter.WriteMultiPrecisionInteger(TestBytes.FromHex("09a378f9b2e332a7"));
                results[1] = bigOut.WrittenSpan.SequenceEqual(TestBytes.FromHex("0000000809a378f9b2e332a7"));

                ArrayBufferWriter<byte> signOut = new ArrayBufferWriter<byte>();
                SshWireWriter signWriter = new SshWireWriter(signOut);
                signWriter.WriteMultiPrecisionInteger(TestBytes.FromHex("80"));
                results[2] = signOut.WrittenSpan.SequenceEqual(TestBytes.FromHex("000000020080"));

                return results;
            })
        .TheTest
        .ShouldPass(because =>
        {
            bool[] results = (bool[])because.Result;
            because.ItsTrue("zero encodes as an empty string", results[0]);
            because.ItsTrue("9a378f9b2e332a7 matches the RFC example", results[1]);
            because.ItsTrue("80 gains a leading 0x00 sign byte per the RFC example", results[2]);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RoundTripNegativeMpintRfcExamplesRaw()
    {
        When.A<ArrayBufferWriter<byte>>("round-trips the RFC's negative mpint vectors via raw two's complement",
            new ArrayBufferWriter<byte>(),
            (output) =>
            {
                byte[] minus1234 = TestBytes.FromHex("edcc");
                byte[] minusDeadBeef = TestBytes.FromHex("ff21524111");

                SshWireWriter writer = new SshWireWriter(output);
                writer.WriteMultiPrecisionIntegerRaw(minus1234);
                writer.WriteMultiPrecisionIntegerRaw(minusDeadBeef);

                bool[] results = new bool[3];
                results[0] = output.WrittenSpan.SequenceEqual(TestBytes.FromHex("00000002edcc00000005ff21524111"));

                SshWireReader reader = new SshWireReader(output.WrittenSpan);
                results[1] = reader.ReadMultiPrecisionInteger().SequenceEqual(minus1234);
                results[2] = reader.ReadMultiPrecisionInteger().SequenceEqual(minusDeadBeef);
                return results;
            })
        .TheTest
        .ShouldPass(because =>
        {
            bool[] results = (bool[])because.Result;
            because.ItsTrue("encoded bytes match the RFC examples", results[0]);
            because.ItsTrue("-1234 body reads back verbatim", results[1]);
            because.ItsTrue("-deadbeef body reads back verbatim", results[2]);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RejectTruncatedReads()
    {
        When.A<ArrayBufferWriter<byte>>("throws SshWireFormatException for every truncated read",
            new ArrayBufferWriter<byte>(),
            (output) =>
            {
                bool[] results = new bool[4];
                results[0] = Throws(() =>
                {
                    SshWireReader reader = new SshWireReader(ReadOnlySpan<byte>.Empty);
                    reader.ReadByte();
                });
                results[1] = Throws(() =>
                {
                    SshWireReader reader = new SshWireReader(new byte[] { 0x01, 0x02 });
                    reader.ReadUInt32();
                });
                results[2] = Throws(() =>
                {
                    SshWireReader reader = new SshWireReader(new byte[7]);
                    reader.ReadUInt64();
                });
                results[3] = Throws(() =>
                {
                    SshWireReader reader = new SshWireReader(TestBytes.FromHex("0000000A0102"));
                    reader.ReadString();
                });
                return results;
            })
        .TheTest
        .ShouldPass(because =>
        {
            bool[] results = (bool[])because.Result;
            because.ItsTrue("ReadByte on empty buffer throws", results[0]);
            because.ItsTrue("ReadUInt32 on two bytes throws", results[1]);
            because.ItsTrue("ReadUInt64 on seven bytes throws", results[2]);
            because.ItsTrue("string length exceeding remaining bytes throws", results[3]);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RejectNonMinimalAndInvalidInput()
    {
        When.A<ArrayBufferWriter<byte>>("rejects non-minimal mpints and malformed name-lists",
            new ArrayBufferWriter<byte>(),
            (output) =>
            {
                bool[] results = new bool[5];
                results[0] = Throws(() =>
                {
                    SshWireReader reader = new SshWireReader(TestBytes.FromHex("00000002007f"));
                    reader.ReadMultiPrecisionInteger();
                });
                results[1] = Throws(() =>
                {
                    SshWireReader reader = new SshWireReader(TestBytes.FromHex("00000002ff80"));
                    reader.ReadMultiPrecisionInteger();
                });
                results[2] = Throws(() =>
                {
                    SshWireReader reader = new SshWireReader(TestBytes.FromHex("0000000200 80".Replace(" ", string.Empty)));
                    reader.ReadMultiPrecisionIntegerMagnitude();
                });
                results[2] = !results[2];
                results[3] = Throws(() => SshNameList.Parse(TestBytes.FromHex("2c7a6c6962")));
                results[4] = Throws(() => SshNameList.Parse(new byte[] { 0x7a, 0x6c, 0x69, 0x62, 0xFF }));
                return results;
            })
        .TheTest
        .ShouldPass(because =>
        {
            bool[] results = (bool[])because.Result;
            because.ItsTrue("unnecessary leading 0x00 is rejected", results[0]);
            because.ItsTrue("unnecessary leading 0xFF is rejected", results[1]);
            because.ItsTrue("necessary sign byte 00 80 is accepted as magnitude", results[2]);
            because.ItsTrue("name-list with leading comma is rejected", results[3]);
            because.ItsTrue("name-list with non-ASCII byte is rejected", results[4]);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    private static bool Throws(Action action)
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
