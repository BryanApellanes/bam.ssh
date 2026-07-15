using System.IO.Pipelines;
using Bam.Ssh.Transport;
using Bam.Test;

namespace Bam.Ssh.Tests.Unit;

[UnitTestMenu("SshPacketPipelineShould", Selector = "spp")]
public class SshPacketPipelineShould : UnitTestMenuContainer
{
    [UnitTest]
    public void RoundTripPayloadsThroughNoneCipher()
    {
        When.A<object>("writes and reads payloads 0-4096 back intact with sequence numbers in lockstep",
            new object(),
            (ignored) =>
            {
                Pipe pipe = new Pipe();
                SshPacketWriter writer = new SshPacketWriter(pipe.Writer, NonePacketCipher.Instance);
                SshPacketReader reader = new SshPacketReader(pipe.Reader, NonePacketCipher.Instance);

                int failures = 0;
                int[] sizes = new int[] { 0, 1, 5, 6, 16, 255, 256, 1024, 4096 };
                foreach (int size in sizes)
                {
                    byte[] payload = new byte[size == 0 ? 1 : size];
                    for (int i = 0; i < payload.Length; i++)
                    {
                        payload[i] = (byte)(i + size);
                    }

                    writer.WriteAsync(payload).AsTask().GetAwaiter().GetResult();
                    using SshIncomingPacket packet = reader.ReadAsync().AsTask().GetAwaiter().GetResult();
                    if (!packet.Payload.SequenceEqual(payload))
                    {
                        failures++;
                    }
                }

                bool sequencesAligned = writer.NextSequenceNumber == (uint)sizes.Length
                    && reader.NextSequenceNumber == (uint)sizes.Length;
                return new int[] { failures, sequencesAligned ? 1 : 0 };
            })
        .TheTest
        .ShouldPass(because =>
        {
            int[] results = (int[])because.Result;
            because.ItsTrue("every payload round-tripped intact", results[0] == 0);
            because.ItsTrue("send and receive sequence numbers advanced in lockstep", results[1] == 1);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void StreamMultiplePacketsWrittenBeforeReading()
    {
        When.A<object>("reads three packets queued before any read",
            new object(),
            (ignored) =>
            {
                Pipe pipe = new Pipe();
                SshPacketWriter writer = new SshPacketWriter(pipe.Writer, NonePacketCipher.Instance);
                SshPacketReader reader = new SshPacketReader(pipe.Reader, NonePacketCipher.Instance);

                byte[][] payloads = new byte[][]
                {
                    new byte[] { 20, 1, 2, 3 },
                    new byte[] { 21 },
                    new byte[] { 80, 9, 8, 7, 6, 5 }
                };
                foreach (byte[] payload in payloads)
                {
                    writer.WriteAsync(payload).AsTask().GetAwaiter().GetResult();
                }

                int matches = 0;
                for (int i = 0; i < payloads.Length; i++)
                {
                    using SshIncomingPacket packet = reader.ReadAsync().AsTask().GetAwaiter().GetResult();
                    if (packet.MessageNumber == payloads[i][0] && packet.Payload.SequenceEqual(payloads[i]))
                    {
                        matches++;
                    }
                }
                return matches;
            })
        .TheTest
        .ShouldPass(because =>
        {
            because.ItsTrue("all three queued packets read back correctly in order", (int)because.Result == 3);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void ExposeMessageNumberAndBody()
    {
        When.A<object>("splits the payload into message number and body",
            new object(),
            (ignored) =>
            {
                Pipe pipe = new Pipe();
                SshPacketWriter writer = new SshPacketWriter(pipe.Writer, NonePacketCipher.Instance);
                SshPacketReader reader = new SshPacketReader(pipe.Reader, NonePacketCipher.Instance);

                byte[] payload = new byte[] { (byte)SshMessageNumber.KexInit, 0xAA, 0xBB, 0xCC };
                writer.WriteAsync(payload).AsTask().GetAwaiter().GetResult();
                using SshIncomingPacket packet = reader.ReadAsync().AsTask().GetAwaiter().GetResult();

                bool numberCorrect = packet.MessageNumber == (byte)SshMessageNumber.KexInit;
                bool bodyCorrect = packet.Body.SequenceEqual(new byte[] { 0xAA, 0xBB, 0xCC });
                return new bool[] { numberCorrect, bodyCorrect };
            })
        .TheTest
        .ShouldPass(because =>
        {
            bool[] results = (bool[])because.Result;
            because.ItsTrue("the message number is the first payload byte", results[0]);
            because.ItsTrue("the body is the payload after the message number", results[1]);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }
}
