using System.Buffers;
using System.Buffers.Binary;
using Bam.Test;

namespace Bam.Ssh.Tests.Unit;

[UnitTestMenu("SshPacketDecoderShould", Selector = "spd")]
public class SshPacketDecoderShould : UnitTestMenuContainer
{
    [UnitTest]
    public void ReassembleFramesDeliveredByteAtATime()
    {
        When.A<SshPacketDecoder>("returns false until the last byte arrives, then decodes",
            new SshPacketDecoder(),
            (decoder) =>
            {
                byte[] encoded = EncodeFrame(new byte[] { 0x15, 0xAA, 0xBB });
                int prematureDecodes = 0;
                for (int available = 0; available < encoded.Length; available++)
                {
                    ReadOnlySequence<byte> partial = new ReadOnlySequence<byte>(encoded.AsMemory(0, available));
                    if (decoder.TryDecode(ref partial, out SshPacketFrame _))
                    {
                        prematureDecodes++;
                    }
                }
                ReadOnlySequence<byte> complete = new ReadOnlySequence<byte>(encoded);
                bool decoded = decoder.TryDecode(ref complete, out SshPacketFrame frame);
                bool payloadIntact = decoded && TestBytes.SequenceEqual(frame.Payload, new byte[] { 0x15, 0xAA, 0xBB });
                bool consumed = complete.Length == 0;
                return new int[] { prematureDecodes, decoded ? 1 : 0, payloadIntact ? 1 : 0, consumed ? 1 : 0 };
            })
        .TheTest
        .ShouldPass(because =>
        {
            int[] results = (int[])because.Result;
            because.ItsTrue("no partial delivery produced a frame", results[0] == 0);
            because.ItsTrue("the complete buffer decoded", results[1] == 1);
            because.ItsTrue("the payload survived intact", results[2] == 1);
            because.ItsTrue("the buffer advanced past the frame", results[3] == 1);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void DecodeMultipleFramesFromOneBuffer()
    {
        When.A<SshPacketDecoder>("decodes three concatenated frames in order",
            new SshPacketDecoder(),
            (decoder) =>
            {
                byte[][] payloads = new byte[][]
                {
                    new byte[] { 0x01 },
                    new byte[] { 0x02, 0x03 },
                    Array.Empty<byte>()
                };
                List<byte> concatenated = new List<byte>();
                foreach (byte[] payload in payloads)
                {
                    concatenated.AddRange(EncodeFrame(payload));
                }
                ReadOnlySequence<byte> buffer = new ReadOnlySequence<byte>(concatenated.ToArray());

                int decodedCount = 0;
                bool allIntact = true;
                while (decoder.TryDecode(ref buffer, out SshPacketFrame frame))
                {
                    if (!TestBytes.SequenceEqual(frame.Payload, payloads[decodedCount]))
                    {
                        allIntact = false;
                    }
                    decodedCount++;
                }
                return new int[] { decodedCount, allIntact ? 1 : 0, buffer.Length == 0 ? 1 : 0 };
            })
        .TheTest
        .ShouldPass(because =>
        {
            int[] results = (int[])because.Result;
            because.ItsTrue("all three frames decoded", results[0] == 3);
            because.ItsTrue("every payload matched in order", results[1] == 1);
            because.ItsTrue("the buffer is fully consumed", results[2] == 1);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void DecodeAcrossMultiSegmentSequences()
    {
        When.A<SshPacketDecoder>("decodes frames split across non-contiguous segments",
            new SshPacketDecoder(),
            (decoder) =>
            {
                byte[] payload = new byte[] { 0x5E, 0x01, 0x02, 0x03, 0x04, 0x05 };
                byte[] encoded = EncodeFrame(payload);

                int failures = 0;
                for (int split = 1; split < encoded.Length - 1; split++)
                {
                    ReadOnlySequence<byte> buffer = TestBytes.MultiSegment(encoded, split);
                    if (!decoder.TryDecode(ref buffer, out SshPacketFrame frame)
                        || !TestBytes.SequenceEqual(frame.Payload, payload)
                        || buffer.Length != 0)
                    {
                        failures++;
                    }
                }
                ReadOnlySequence<byte> threeWay = TestBytes.MultiSegment(encoded, 2, 7);
                if (!decoder.TryDecode(ref threeWay, out SshPacketFrame threeWayFrame)
                    || !TestBytes.SequenceEqual(threeWayFrame.Payload, payload))
                {
                    failures++;
                }
                return failures;
            })
        .TheTest
        .ShouldPass(because =>
        {
            because.ItsTrue("every split position decoded the frame intact", (int)because.Result == 0);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RejectProtocolViolationsBeforeBuffering()
    {
        When.A<SshPacketDecoder>("throws SshPacketFormatException with ProtocolError for each violation",
            new SshPacketDecoder(),
            (decoder) =>
            {
                bool[] results = new bool[4];
                results[0] = ThrowsProtocolError(decoder, TestBytes.FromHex("00000004"));
                results[1] = ThrowsProtocolError(decoder, TestBytes.FromHex("00040001"));
                results[2] = ThrowsProtocolError(decoder, BuildRawFrame(packetLength: 8, paddingLength: 3));
                results[3] = ThrowsProtocolError(decoder, BuildRawFrame(packetLength: 8, paddingLength: 8));
                return results;
            })
        .TheTest
        .ShouldPass(because =>
        {
            bool[] results = (bool[])because.Result;
            because.ItsTrue("packet_length below 5 is rejected", results[0]);
            because.ItsTrue("packet_length above the limit is rejected without waiting for bytes", results[1]);
            because.ItsTrue("padding_length below 4 is rejected", results[2]);
            because.ItsTrue("padding_length that exceeds the packet is rejected", results[3]);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void LeaveBufferUntouchedWhenIncomplete()
    {
        When.A<SshPacketDecoder>("does not consume bytes when a frame is incomplete",
            new SshPacketDecoder(),
            (decoder) =>
            {
                byte[] encoded = EncodeFrame(new byte[] { 0x63 });
                ReadOnlySequence<byte> partial = new ReadOnlySequence<byte>(encoded.AsMemory(0, encoded.Length - 1));
                long before = partial.Length;
                bool decoded = decoder.TryDecode(ref partial, out SshPacketFrame _);
                return new long[] { decoded ? 1 : 0, before, partial.Length };
            })
        .TheTest
        .ShouldPass(because =>
        {
            long[] results = (long[])because.Result;
            because.ItsTrue("no frame was produced", results[0] == 0);
            because.ItsTrue("the buffer length is unchanged", results[1] == results[2]);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    private static byte[] EncodeFrame(byte[] payload)
    {
        SshPacketEncoder encoder = new SshPacketEncoder(new FakeSshRandom(0x99));
        ArrayBufferWriter<byte> output = new ArrayBufferWriter<byte>();
        SshPacketGeometry geometry = SshPacketGeometry.Default;
        encoder.Encode(payload, output, in geometry);
        return output.WrittenSpan.ToArray();
    }

    private static byte[] BuildRawFrame(uint packetLength, byte paddingLength)
    {
        byte[] frame = new byte[4 + packetLength];
        BinaryPrimitives.WriteUInt32BigEndian(frame, packetLength);
        frame[4] = paddingLength;
        return frame;
    }

    private static bool ThrowsProtocolError(SshPacketDecoder decoder, byte[] input)
    {
        try
        {
            ReadOnlySequence<byte> buffer = new ReadOnlySequence<byte>(input);
            decoder.TryDecode(ref buffer, out SshPacketFrame _);
            return false;
        }
        catch (SshPacketFormatException exception)
        {
            return exception.Reason == SshDisconnectReason.ProtocolError;
        }
    }
}
