using System.Buffers;

namespace Bam.Ssh.Sftp;

/// <summary>
/// One received SFTP message: its <see cref="Type"/> and the payload bytes after the type byte, held in a
/// pooled buffer. Parse the payload with <see cref="CreateReader"/> (synchronously, before disposing), then
/// dispose to return the buffer to the pool.
/// </summary>
public readonly struct SftpMessage : IDisposable
{
    private readonly byte[] _buffer;
    private readonly int _length;

    internal SftpMessage(SftpPacketType type, byte[] buffer, int length)
    {
        Type = type;
        _buffer = buffer;
        _length = length;
    }

    /// <summary>Gets the message type.</summary>
    public SftpPacketType Type { get; }

    /// <summary>Gets the payload bytes (everything after the one-byte type).</summary>
    public ReadOnlySpan<byte> Payload => _buffer.AsSpan(1, _length - 1);

    /// <summary>
    /// Creates a wire reader over the payload. The returned reader is valid until this message is disposed.
    /// </summary>
    /// <returns>A reader positioned at the start of the payload.</returns>
    public SshWireReader CreateReader()
    {
        return new SshWireReader(Payload);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_buffer != null)
        {
            ArrayPool<byte>.Shared.Return(_buffer);
        }
    }
}
