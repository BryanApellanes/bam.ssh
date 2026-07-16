using System.Buffers;
using System.Collections.Concurrent;
using System.IO.Pipelines;
using Bam.Ssh.Transport;

namespace Bam.Ssh.Connection;

/// <summary>
/// One RFC 4254 channel multiplexed over an <see cref="SshConnection"/>: a full-duplex byte stream
/// with independent send/receive flow-control windows, a separate extended-data (stderr) stream, named
/// channel requests in both directions, and half-close via EOF/CLOSE. It is transport-generic and
/// carries no session semantics — <see cref="SshSessionChannel"/> composes it to add those. Inbound
/// bytes are buffered into <see cref="System.IO.Pipelines"/> pipes by the connection's dispatch loop
/// and drained by the consumer through <see cref="ReadAsync"/>/<see cref="ReadExtendedAsync"/>, which
/// is what replenishes the receive window. Outbound writes are chunked to the peer's maximum packet
/// size and metered by the send window.
/// </summary>
public sealed class SshChannel
{
    private static readonly PipeOptions ChannelPipeOptions = new PipeOptions(
        pauseWriterThreshold: 0,
        resumeWriterThreshold: 0,
        useSynchronizationContext: false);

    private readonly SshConnection _connection;
    private readonly uint _localId;
    private readonly string _channelType;
    private readonly SshReceiveWindow _receiveWindow;
    private readonly Pipe _dataPipe = new Pipe(ChannelPipeOptions);
    private readonly Pipe _extendedPipe = new Pipe(ChannelPipeOptions);
    private readonly SemaphoreSlim _writeLock = new SemaphoreSlim(1, 1);
    private readonly ConcurrentQueue<TaskCompletionSource<bool>> _pendingRequests = new ConcurrentQueue<TaskCompletionSource<bool>>();
    private readonly TaskCompletionSource<SshChannel> _openCompletion =
        new TaskCompletionSource<SshChannel>(TaskCreationOptions.RunContinuationsAsynchronously);

    private uint _remoteId;
    private int _remoteMaximumPacketSize;
    private SshSendWindow? _sendWindow;
    private bool _sentEof;
    private bool _sentClose;
    private bool _receivedClose;

    internal SshChannel(SshConnection connection, uint localId, string channelType, int initialReceiveWindow)
    {
        _connection = connection;
        _localId = localId;
        _channelType = channelType;
        _receiveWindow = new SshReceiveWindow(initialReceiveWindow);
    }

    /// <summary>
    /// Raised when the peer sends a channel request this channel did not consume itself. The generic
    /// channel replies CHANNEL_FAILURE to any such request that set <c>want_reply</c>.
    /// </summary>
    public event EventHandler<SshChannelRequestEventArgs>? RequestReceived;

    /// <summary>
    /// Gets this side's channel identifier (the recipient id the peer addresses in its messages).
    /// </summary>
    public uint LocalId => _localId;

    /// <summary>
    /// Gets the peer's channel identifier (valid after the channel is open).
    /// </summary>
    public uint RemoteId => _remoteId;

    /// <summary>
    /// Gets the channel type name.
    /// </summary>
    public string ChannelType => _channelType;

    internal Task<SshChannel> OpenCompletion => _openCompletion.Task;

    /// <summary>
    /// Reads the next available channel data (stdout stream) into <paramref name="buffer"/>. Returns
    /// the number of bytes read, or zero once the peer has signalled EOF/CLOSE and the buffer is drained.
    /// </summary>
    /// <param name="buffer">The destination buffer.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>The number of bytes read; zero at end of stream.</returns>
    public ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        return ReadFromAsync(_dataPipe.Reader, buffer, cancellationToken);
    }

    /// <summary>
    /// Reads the next available extended data (stderr stream) into <paramref name="buffer"/>. Returns
    /// the number of bytes read, or zero once the stream ends.
    /// </summary>
    /// <param name="buffer">The destination buffer.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>The number of bytes read; zero at end of stream.</returns>
    public ValueTask<int> ReadExtendedAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        return ReadFromAsync(_extendedPipe.Reader, buffer, cancellationToken);
    }

    /// <summary>
    /// Writes data to the channel, chunked to the peer's maximum packet size and metered by the send
    /// window (awaiting a WINDOW_ADJUST when the window is exhausted).
    /// </summary>
    /// <param name="data">The bytes to send.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <exception cref="SshChannelException">The channel is not open, or EOF/CLOSE has been sent.</exception>
    public async ValueTask WriteAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
    {
        SshSendWindow window = EnsureOpen();
        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_sentEof || _sentClose)
            {
                throw new SshChannelException("Cannot write to a channel after EOF or CLOSE has been sent.");
            }
            int offset = 0;
            while (offset < data.Length)
            {
                int want = Math.Min(data.Length - offset, _remoteMaximumPacketSize);
                int granted = await window.ReserveAsync(want, cancellationToken).ConfigureAwait(false);
                await SendDataAsync(data.Slice(offset, granted), cancellationToken).ConfigureAwait(false);
                offset += granted;
            }
        }
        finally
        {
            _writeLock.Release();
        }
    }

    /// <summary>
    /// Writes extended data (e.g. standard error) to the channel, chunked and metered exactly like
    /// <see cref="WriteAsync"/>. Used by the server role to send a command's stderr stream.
    /// </summary>
    /// <param name="dataType">The extended-data type (e.g. <see cref="SshExtendedDataType.StandardError"/>).</param>
    /// <param name="data">The bytes to send.</param>
    /// <param name="cancellationToken">Cancels the write.</param>
    /// <exception cref="SshChannelException">The channel is not open, or EOF/CLOSE has been sent.</exception>
    public async ValueTask WriteExtendedAsync(SshExtendedDataType dataType, ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
    {
        SshSendWindow window = EnsureOpen();
        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_sentEof || _sentClose)
            {
                throw new SshChannelException("Cannot write to a channel after EOF or CLOSE has been sent.");
            }
            int offset = 0;
            while (offset < data.Length)
            {
                int want = Math.Min(data.Length - offset, _remoteMaximumPacketSize);
                int granted = await window.ReserveAsync(want, cancellationToken).ConfigureAwait(false);
                await SendExtendedDataAsync(dataType, data.Slice(offset, granted), cancellationToken).ConfigureAwait(false);
                offset += granted;
            }
        }
        finally
        {
            _writeLock.Release();
        }
    }

    /// <summary>
    /// Sends a channel request (RFC 4254 §5.4). When <paramref name="wantReply"/> is set, awaits the
    /// peer's CHANNEL_SUCCESS/CHANNEL_FAILURE and returns whether it succeeded; otherwise returns true.
    /// </summary>
    /// <param name="requestType">The request type name.</param>
    /// <param name="wantReply">Whether to request and await a reply.</param>
    /// <param name="requestData">The request-type-specific bytes.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>True on success (or when no reply was requested); false if the peer replied FAILURE.</returns>
    /// <exception cref="ArgumentNullException">The request type is null.</exception>
    public async ValueTask<bool> SendRequestAsync(string requestType, bool wantReply, ReadOnlyMemory<byte> requestData, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(requestType);
        EnsureOpen();

        TaskCompletionSource<bool>? reply = null;
        if (wantReply)
        {
            reply = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            _pendingRequests.Enqueue(reply);
        }

        using (PooledBufferWriter writer = new PooledBufferWriter(32 + requestData.Length))
        {
            SshWireWriter wire = new SshWireWriter(writer);
            wire.WriteByte((byte)SshMessageNumber.ChannelRequest);
            wire.WriteUInt32(_remoteId);
            wire.WriteText(requestType);
            wire.WriteBoolean(wantReply);
            wire.WriteRaw(requestData.Span);
            await _connection.SendAsync(writer.WrittenMemory, cancellationToken).ConfigureAwait(false);
        }

        if (reply == null)
        {
            return true;
        }
        return await reply.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Sends SSH_MSG_CHANNEL_EOF, signalling that no more data will be written to the channel. Data may
    /// still be received until the peer closes.
    /// </summary>
    /// <param name="cancellationToken">Cancels the send.</param>
    public async ValueTask SendEofAsync(CancellationToken cancellationToken = default)
    {
        EnsureOpen();
        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_sentEof || _sentClose)
            {
                return;
            }
            _sentEof = true;
            byte[] payload = BuildSingleIdMessage(SshMessageNumber.ChannelEof);
            await _connection.SendAsync(payload, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    /// <summary>
    /// Sends SSH_MSG_CHANNEL_CLOSE. The channel is fully torn down once both sides have closed.
    /// </summary>
    /// <param name="cancellationToken">Cancels the send.</param>
    public async ValueTask CloseAsync(CancellationToken cancellationToken = default)
    {
        EnsureOpen();
        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        bool alreadyClosed;
        try
        {
            alreadyClosed = _sentClose;
            _sentClose = true;
        }
        finally
        {
            _writeLock.Release();
        }
        if (alreadyClosed)
        {
            return;
        }
        byte[] payload = BuildSingleIdMessage(SshMessageNumber.ChannelClose);
        await _connection.SendAsync(payload, cancellationToken).ConfigureAwait(false);
        FinalizeIfClosed();
    }

    internal void CompleteOpen(uint remoteId, uint initialSendWindow, uint remoteMaximumPacketSize)
    {
        _remoteId = remoteId;
        _remoteMaximumPacketSize = remoteMaximumPacketSize == 0 ? 1 : (int)Math.Min(remoteMaximumPacketSize, int.MaxValue);
        _sendWindow = new SshSendWindow(initialSendWindow);
        _openCompletion.TrySetResult(this);
    }

    internal void FailOpen(SshChannelOpenFailureReason reason, string description)
    {
        _openCompletion.TrySetException(
            new SshChannelException($"The peer refused the channel open ({reason}): {description}"));
    }

    internal void AcceptData(ReadOnlySpan<byte> data)
    {
        _receiveWindow.RecordReceived(data.Length);
        WriteToPipe(_dataPipe.Writer, data);
    }

    internal void AcceptExtendedData(uint dataTypeCode, ReadOnlySpan<byte> data)
    {
        _receiveWindow.RecordReceived(data.Length);
        // Only the standard-error type is carried into a separate stream; unknown codes still count
        // against the window and are surfaced on the extended stream so no bytes are silently dropped.
        WriteToPipe(_extendedPipe.Writer, data);
    }

    internal void AcceptWindowAdjust(uint bytesToAdd)
    {
        _sendWindow?.Adjust(bytesToAdd);
    }

    internal void AcceptEof()
    {
        _dataPipe.Writer.Complete();
        _extendedPipe.Writer.Complete();
    }

    internal void AcceptRequestReply(bool success)
    {
        if (_pendingRequests.TryDequeue(out TaskCompletionSource<bool>? reply))
        {
            reply.TrySetResult(success);
        }
    }

    internal void AcceptRequest(string requestType, bool wantReply, ReadOnlyMemory<byte> requestData)
    {
        SshChannelRequestEventArgs args = new SshChannelRequestEventArgs(this, requestType, wantReply, requestData);
        RequestReceived?.Invoke(this, args);
        if (wantReply && !args.WasReplied)
        {
            // No subscriber accepted the request (or there is none); reply FAILURE.
            _connection.PostSend(BuildSingleIdMessage(SshMessageNumber.ChannelFailure));
        }
    }

    internal void PostRequestReply(bool success)
    {
        _connection.PostSend(BuildSingleIdMessage(success ? SshMessageNumber.ChannelSuccess : SshMessageNumber.ChannelFailure));
    }

    internal void AcceptClose()
    {
        _receivedClose = true;
        _dataPipe.Writer.Complete();
        _extendedPipe.Writer.Complete();
        _sendWindow?.Close();
        if (!_sentClose)
        {
            _sentClose = true;
            _connection.PostSend(BuildSingleIdMessage(SshMessageNumber.ChannelClose));
        }
        FinalizeIfClosed();
    }

    internal void Fault(Exception exception)
    {
        _openCompletion.TrySetException(exception);
        _dataPipe.Writer.Complete(exception);
        _extendedPipe.Writer.Complete(exception);
        _sendWindow?.Close();
        while (_pendingRequests.TryDequeue(out TaskCompletionSource<bool>? reply))
        {
            reply.TrySetException(exception);
        }
    }

    private void FinalizeIfClosed()
    {
        if (_sentClose && _receivedClose)
        {
            _connection.RemoveChannel(_localId);
        }
    }

    private async ValueTask SendDataAsync(ReadOnlyMemory<byte> chunk, CancellationToken cancellationToken)
    {
        using PooledBufferWriter writer = new PooledBufferWriter(16 + chunk.Length);
        SshWireWriter wire = new SshWireWriter(writer);
        wire.WriteByte((byte)SshMessageNumber.ChannelData);
        wire.WriteUInt32(_remoteId);
        wire.WriteString(chunk.Span);
        await _connection.SendAsync(writer.WrittenMemory, cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask SendExtendedDataAsync(SshExtendedDataType dataType, ReadOnlyMemory<byte> chunk, CancellationToken cancellationToken)
    {
        using PooledBufferWriter writer = new PooledBufferWriter(20 + chunk.Length);
        SshWireWriter wire = new SshWireWriter(writer);
        wire.WriteByte((byte)SshMessageNumber.ChannelExtendedData);
        wire.WriteUInt32(_remoteId);
        wire.WriteUInt32((uint)dataType);
        wire.WriteString(chunk.Span);
        await _connection.SendAsync(writer.WrittenMemory, cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask<int> ReadFromAsync(PipeReader reader, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        if (buffer.IsEmpty)
        {
            return 0;
        }
        while (true)
        {
            ReadResult result = await reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            ReadOnlySequence<byte> sequence = result.Buffer;
            if (sequence.IsEmpty)
            {
                if (result.IsCompleted)
                {
                    reader.AdvanceTo(sequence.End);
                    return 0;
                }
                reader.AdvanceTo(sequence.Start, sequence.End);
                continue;
            }

            int toCopy = (int)Math.Min(buffer.Length, sequence.Length);
            sequence.Slice(0, toCopy).CopyTo(buffer.Span);
            reader.AdvanceTo(sequence.GetPosition(toCopy));

            uint increment = _receiveWindow.RecordConsumed(toCopy);
            if (increment > 0)
            {
                await SendWindowAdjustAsync(increment, cancellationToken).ConfigureAwait(false);
            }
            return toCopy;
        }
    }

    private async ValueTask SendWindowAdjustAsync(uint increment, CancellationToken cancellationToken)
    {
        using PooledBufferWriter writer = new PooledBufferWriter(9);
        SshWireWriter wire = new SshWireWriter(writer);
        wire.WriteByte((byte)SshMessageNumber.ChannelWindowAdjust);
        wire.WriteUInt32(_remoteId);
        wire.WriteUInt32(increment);
        await _connection.SendAsync(writer.WrittenMemory, cancellationToken).ConfigureAwait(false);
    }

    private byte[] BuildSingleIdMessage(SshMessageNumber messageNumber)
    {
        byte[] payload = new byte[5];
        payload[0] = (byte)messageNumber;
        payload[1] = (byte)(_remoteId >> 24);
        payload[2] = (byte)(_remoteId >> 16);
        payload[3] = (byte)(_remoteId >> 8);
        payload[4] = (byte)_remoteId;
        return payload;
    }

    private static void WriteToPipe(PipeWriter writer, ReadOnlySpan<byte> data)
    {
        Span<byte> destination = writer.GetSpan(data.Length);
        data.CopyTo(destination);
        writer.Advance(data.Length);
        // The pipe is configured with pausing disabled, so this flush always completes synchronously;
        // the SSH receive window (not the pipe) bounds how much unread data can accumulate.
        ValueTask<FlushResult> flush = writer.FlushAsync();
        if (!flush.IsCompletedSuccessfully)
        {
            flush.AsTask().GetAwaiter().GetResult();
        }
        else
        {
            _ = flush.Result;
        }
    }

    private SshSendWindow EnsureOpen()
    {
        SshSendWindow? window = _sendWindow;
        if (window == null)
        {
            throw new SshChannelException("The channel is not open.");
        }
        return window;
    }
}
