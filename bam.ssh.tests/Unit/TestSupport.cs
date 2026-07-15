using System.Buffers;

namespace Bam.Ssh.Tests.Unit;

internal sealed class FakeSshRandom : ISshRandom
{
    private readonly byte _fillValue;

    public FakeSshRandom(byte fillValue)
    {
        _fillValue = fillValue;
    }

    public void Fill(Span<byte> destination)
    {
        destination.Fill(_fillValue);
    }
}

internal sealed class MemorySegment : ReadOnlySequenceSegment<byte>
{
    public MemorySegment(ReadOnlyMemory<byte> memory)
    {
        Memory = memory;
    }

    public MemorySegment Append(ReadOnlyMemory<byte> memory)
    {
        MemorySegment next = new MemorySegment(memory)
        {
            RunningIndex = RunningIndex + Memory.Length
        };
        Next = next;
        return next;
    }
}

internal static class TestBytes
{
    public static ReadOnlySequence<byte> MultiSegment(byte[] bytes, params int[] splitOffsets)
    {
        List<byte[]> chunks = new List<byte[]>();
        int start = 0;
        foreach (int offset in splitOffsets)
        {
            chunks.Add(bytes[start..offset]);
            start = offset;
        }
        chunks.Add(bytes[start..]);

        MemorySegment first = new MemorySegment(chunks[0]);
        MemorySegment last = first;
        for (int i = 1; i < chunks.Count; i++)
        {
            last = last.Append(chunks[i]);
        }
        return new ReadOnlySequence<byte>(first, 0, last, last.Memory.Length);
    }

    public static byte[] FromHex(string hex)
    {
        return Convert.FromHexString(hex.Replace(" ", string.Empty));
    }

    public static bool SequenceEqual(ReadOnlySequence<byte> actual, byte[] expected)
    {
        if (actual.Length != expected.Length)
        {
            return false;
        }
        byte[] linear = actual.ToArray();
        return linear.AsSpan().SequenceEqual(expected);
    }
}
