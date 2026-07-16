namespace Bam.Ssh.Authentication;

/// <summary>
/// Writes fields into an <see cref="SshWireWriter"/> that wraps a pooled buffer. A custom delegate is
/// used (rather than <see cref="Action{T}"/>) because <see cref="SshWireWriter"/> is a ref struct and
/// cannot be a generic type argument.
/// </summary>
/// <param name="writer">The wire writer to append fields to.</param>
internal delegate void SshWireWriteCallback(ref SshWireWriter writer);

/// <summary>
/// Builds length-prefixed SSH blobs (public-key blobs, signature blobs, signed request data) into a
/// pooled buffer and returns the exact bytes, centralizing the
/// <see cref="PooledBufferWriter"/> + <see cref="SshWireWriter"/> pattern the signers and methods share.
/// </summary>
internal static class SshSignatureBlob
{
    /// <summary>
    /// Runs the callback against a fresh wire writer over a pooled buffer and returns the written bytes.
    /// </summary>
    /// <param name="write">Appends the blob's fields.</param>
    /// <returns>A copy of the written bytes.</returns>
    public static byte[] Build(SshWireWriteCallback write)
    {
        using PooledBufferWriter buffer = new PooledBufferWriter(128);
        SshWireWriter writer = new SshWireWriter(buffer);
        write(ref writer);
        return buffer.WrittenSpan.ToArray();
    }
}
