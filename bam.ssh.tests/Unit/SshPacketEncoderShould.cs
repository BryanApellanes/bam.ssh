using System.Buffers;
using System.Buffers.Binary;
using Bam.Test;

namespace Bam.Ssh.Tests.Unit;

[UnitTestMenu("SshPacketEncoderShould", Selector = "spe")]
public class SshPacketEncoderShould : UnitTestMenuContainer
{
    [UnitTest]
    public void PadToBlockMultipleAcrossPayloadSizes()
    {
        When.A<SshPacketEncoder>("keeps every frame block-aligned for payloads 0-1024 across block sizes 8 and 16",
            new SshPacketEncoder(new FakeSshRandom(0xAB)),
            (encoder) =>
            {
                int failures = 0;
                int[] blockSizes = new int[] { 8, 16 };
                foreach (int blockSize in blockSizes)
                {
                    SshPacketGeometry geometry = new SshPacketGeometry(blockSize, true);
                    for (int payloadLength = 0; payloadLength <= 1024; payloadLength++)
                    {
                        byte[] payload = new byte[payloadLength];
                        ArrayBufferWriter<byte> output = new ArrayBufferWriter<byte>();
                        encoder.Encode(payload, output, in geometry);

                        ReadOnlySpan<byte> written = output.WrittenSpan;
                        uint packetLength = BinaryPrimitives.ReadUInt32BigEndian(written);
                        byte paddingLength = written[4];
                        bool aligned = (4 + packetLength) % (uint)blockSize == 0;
                        bool minimumPadding = paddingLength >= 4;
                        bool lengthsConsistent = packetLength == 1u + (uint)payloadLength + paddingLength;
                        bool totalMatches = written.Length == 4 + packetLength;
                        if (!(aligned && minimumPadding && lengthsConsistent && totalMatches))
                        {
                            failures++;
                        }
                    }
                }
                return failures;
            })
        .TheTest
        .ShouldPass(because =>
        {
            because.ItsTrue("no payload size violated alignment, minimum padding, or length consistency",
                (int)because.Result == 0);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void ExcludeLengthFieldFromAlignmentWhenNotEncrypted()
    {
        When.A<SshPacketEncoder>("aligns without the length field for AEAD-style geometry",
            new SshPacketEncoder(new FakeSshRandom(0xCD)),
            (encoder) =>
            {
                int failures = 0;
                SshPacketGeometry geometry = new SshPacketGeometry(16, false);
                for (int payloadLength = 0; payloadLength <= 256; payloadLength++)
                {
                    byte[] payload = new byte[payloadLength];
                    ArrayBufferWriter<byte> output = new ArrayBufferWriter<byte>();
                    encoder.Encode(payload, output, in geometry);
                    uint packetLength = BinaryPrimitives.ReadUInt32BigEndian(output.WrittenSpan);
                    if (packetLength % 16 != 0)
                    {
                        failures++;
                    }
                }
                return failures;
            })
        .TheTest
        .ShouldPass(because =>
        {
            because.ItsTrue("packet_length alone is a multiple of the block size for every payload",
                (int)because.Result == 0);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void FillPaddingFromInjectedRandomness()
    {
        When.A<SshPacketEncoder>("uses the injected ISshRandom for every padding byte",
            new SshPacketEncoder(new FakeSshRandom(0xAB)),
            (encoder) =>
            {
                byte[] payload = new byte[] { 0x14, 0x01, 0x02, 0x03 };
                ArrayBufferWriter<byte> output = new ArrayBufferWriter<byte>();
                SshPacketGeometry geometry = SshPacketGeometry.Default;
                encoder.Encode(payload, output, in geometry);

                ReadOnlySpan<byte> written = output.WrittenSpan;
                byte paddingLength = written[4];
                ReadOnlySpan<byte> padding = written.Slice(5 + payload.Length, paddingLength);
                bool allFromFake = true;
                foreach (byte b in padding)
                {
                    if (b != 0xAB)
                    {
                        allFromFake = false;
                    }
                }
                bool payloadIntact = written.Slice(5, payload.Length).SequenceEqual(payload);
                return new bool[] { allFromFake, payloadIntact };
            })
        .TheTest
        .ShouldPass(because =>
        {
            bool[] results = (bool[])because.Result;
            because.ItsTrue("every padding byte came from the injected source", results[0]);
            because.ItsTrue("the payload is written verbatim", results[1]);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RoundTripThroughDecoder()
    {
        When.A<SshPacketEncoder>("frames that the decoder accepts and payloads that survive intact",
            new SshPacketEncoder(new FakeSshRandom(0x5A)),
            (encoder) =>
            {
                SshPacketDecoder decoder = new SshPacketDecoder();
                SshPacketGeometry geometry = SshPacketGeometry.Default;
                int failures = 0;
                for (int payloadLength = 0; payloadLength <= 128; payloadLength++)
                {
                    byte[] payload = new byte[payloadLength];
                    for (int i = 0; i < payloadLength; i++)
                    {
                        payload[i] = (byte)i;
                    }
                    ArrayBufferWriter<byte> output = new ArrayBufferWriter<byte>();
                    encoder.Encode(payload, output, in geometry);

                    ReadOnlySequence<byte> buffer = new ReadOnlySequence<byte>(output.WrittenMemory);
                    if (!decoder.TryDecode(ref buffer, out SshPacketFrame frame)
                        || !TestBytes.SequenceEqual(frame.Payload, payload)
                        || buffer.Length != 0)
                    {
                        failures++;
                    }
                }
                return failures;
            })
        .TheTest
        .ShouldPass(because =>
        {
            because.ItsTrue("every encoded frame decodes back to its exact payload",
                (int)because.Result == 0);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }
}
