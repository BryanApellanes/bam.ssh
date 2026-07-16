using System.Buffers;
using System.IO.Pipelines;
using Bam.Ssh.Transport;

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

/// <summary>
/// An in-memory <see cref="ISshDuplexStream"/> built from two cross-wired pipes, so a client-side
/// and server-side transport can be tested against each other without any network. Expose the two
/// endpoints via <see cref="CreatePair"/>.
/// </summary>
internal sealed class LoopbackDuplexStream : ISshDuplexStream
{
    private readonly Pipe _inbound;
    private readonly Pipe _outbound;

    private LoopbackDuplexStream(Pipe inbound, Pipe outbound)
    {
        _inbound = inbound;
        _outbound = outbound;
    }

    public PipeReader Input => _inbound.Reader;

    public PipeWriter Output => _outbound.Writer;

    public static (LoopbackDuplexStream Client, LoopbackDuplexStream Server) CreatePair()
    {
        Pipe clientToServer = new Pipe();
        Pipe serverToClient = new Pipe();
        LoopbackDuplexStream client = new LoopbackDuplexStream(serverToClient, clientToServer);
        LoopbackDuplexStream server = new LoopbackDuplexStream(clientToServer, serverToClient);
        return (client, server);
    }

    public ValueTask CloseAsync(CancellationToken cancellationToken = default)
    {
        _outbound.Writer.Complete();
        _inbound.Reader.Complete();
        return ValueTask.CompletedTask;
    }

    public ValueTask DisposeAsync()
    {
        return CloseAsync();
    }
}

/// <summary>
/// An <see cref="ISshLogger"/> that records every message so tests can assert what was logged
/// (e.g. that an SSH_MSG_DEBUG was surfaced).
/// </summary>
internal sealed class CapturingSshLogger : ISshLogger
{
    public List<string> Messages { get; } = new List<string>();

    public bool IsEnabled(SshLogLevel level) => true;

    public void Log(SshLogLevel level, string messageTemplate, params object?[] arguments)
    {
        Messages.Add(string.Format(messageTemplate, arguments));
    }
}

/// <summary>
/// An <see cref="ISshPacketCipher"/> that records how many times it transformed packets, wrapping
/// an inner cipher — used to prove <c>ApplyKeys</c>/<c>SwapCipher</c> actually swaps the active cipher.
/// </summary>
internal sealed class RecordingPacketCipher : ISshPacketCipher
{
    private readonly ISshPacketCipher _inner;

    public RecordingPacketCipher(ISshPacketCipher inner)
    {
        _inner = inner;
    }

    public int OutgoingCount { get; private set; }

    public int IncomingCount { get; private set; }

    public SshPacketGeometry Geometry => _inner.Geometry;

    public int MacLength => _inner.MacLength;

    public int LengthPeekSize => _inner.LengthPeekSize;

    public void TransformOutgoing(ReadOnlySpan<byte> framedPacket, uint sequenceNumber, IBufferWriter<byte> output)
    {
        OutgoingCount++;
        _inner.TransformOutgoing(framedPacket, sequenceNumber, output);
    }

    public uint DecryptLength(ReadOnlySpan<byte> peek, uint sequenceNumber, Span<byte> decryptedLength)
    {
        return _inner.DecryptLength(peek, sequenceNumber, decryptedLength);
    }

    public bool VerifyAndDecrypt(ReadOnlySpan<byte> wirePacket, uint sequenceNumber, IBufferWriter<byte> output)
    {
        IncomingCount++;
        return _inner.VerifyAndDecrypt(wirePacket, sequenceNumber, output);
    }
}
