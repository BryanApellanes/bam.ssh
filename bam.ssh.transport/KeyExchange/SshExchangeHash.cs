using System.Security.Cryptography;

namespace Bam.Ssh.Transport;

/// <summary>
/// Computes the SSH key-exchange hash H (RFC 4253 §8 for finite-field DH, RFC 5656 §4 for ECDH):
/// <c>H = HASH(V_C || V_S || I_C || I_S || K_S || Q_C || Q_S || K)</c> where the version strings,
/// KEXINIT payloads, and host key are SSH strings; the public values <c>Q_C</c>/<c>Q_S</c> (or
/// <c>e</c>/<c>f</c>) are strings or mpints per the method; and the shared secret <c>K</c> is an
/// mpint. H authenticates the whole handshake — the server signs it with its host key — and, on the
/// first exchange, becomes the session identifier.
/// </summary>
public static class SshExchangeHash
{
    /// <summary>
    /// Computes the exchange hash H.
    /// </summary>
    /// <param name="hashAlgorithm">The digest for the negotiated key-exchange method (SHA-256 for the required methods).</param>
    /// <param name="clientIdentification">V_C — the client identification string without CRLF.</param>
    /// <param name="serverIdentification">V_S — the server identification string without CRLF.</param>
    /// <param name="clientKexInitPayload">I_C — the client's full SSH_MSG_KEXINIT payload.</param>
    /// <param name="serverKexInitPayload">I_S — the server's full SSH_MSG_KEXINIT payload.</param>
    /// <param name="hostKeyBlob">K_S — the server's public host key blob.</param>
    /// <param name="clientPublicValue">Q_C or e — the client's key-exchange public value (raw).</param>
    /// <param name="serverPublicValue">Q_S or f — the server's key-exchange public value (raw).</param>
    /// <param name="publicValueFormat">Whether the public values are strings (ECDH) or mpints (DH).</param>
    /// <param name="sharedSecret">K — the shared secret as an unsigned big-endian magnitude.</param>
    /// <returns>The exchange hash H.</returns>
    public static byte[] Compute(
        HashAlgorithmName hashAlgorithm,
        ReadOnlySpan<byte> clientIdentification,
        ReadOnlySpan<byte> serverIdentification,
        ReadOnlySpan<byte> clientKexInitPayload,
        ReadOnlySpan<byte> serverKexInitPayload,
        ReadOnlySpan<byte> hostKeyBlob,
        ReadOnlySpan<byte> clientPublicValue,
        ReadOnlySpan<byte> serverPublicValue,
        SshKeyExchangePublicValueFormat publicValueFormat,
        ReadOnlySpan<byte> sharedSecret)
    {
        using PooledBufferWriter buffer = new PooledBufferWriter(
            clientKexInitPayload.Length + serverKexInitPayload.Length + hostKeyBlob.Length + 256);
        SshWireWriter writer = new SshWireWriter(buffer);
        writer.WriteString(clientIdentification);
        writer.WriteString(serverIdentification);
        writer.WriteString(clientKexInitPayload);
        writer.WriteString(serverKexInitPayload);
        writer.WriteString(hostKeyBlob);
        WritePublicValue(ref writer, clientPublicValue, publicValueFormat);
        WritePublicValue(ref writer, serverPublicValue, publicValueFormat);
        writer.WriteMultiPrecisionInteger(sharedSecret);

        return ComputeDigest(hashAlgorithm, buffer.WrittenSpan);
    }

    /// <summary>
    /// Computes a digest of the given data with the named hash algorithm. Shared with key derivation.
    /// </summary>
    /// <param name="hashAlgorithm">The digest algorithm (SHA-256/384/512).</param>
    /// <param name="data">The data to hash.</param>
    /// <returns>The digest bytes.</returns>
    /// <exception cref="SshKeyExchangeException">The hash algorithm is not supported.</exception>
    public static byte[] ComputeDigest(HashAlgorithmName hashAlgorithm, ReadOnlySpan<byte> data)
    {
        if (hashAlgorithm == HashAlgorithmName.SHA256)
        {
            return SHA256.HashData(data);
        }
        if (hashAlgorithm == HashAlgorithmName.SHA384)
        {
            return SHA384.HashData(data);
        }
        if (hashAlgorithm == HashAlgorithmName.SHA512)
        {
            return SHA512.HashData(data);
        }
        throw new SshKeyExchangeException($"Unsupported key-exchange hash algorithm '{hashAlgorithm.Name}'.");
    }

    private static void WritePublicValue(ref SshWireWriter writer, ReadOnlySpan<byte> value, SshKeyExchangePublicValueFormat format)
    {
        if (format == SshKeyExchangePublicValueFormat.MultiPrecisionInteger)
        {
            writer.WriteMultiPrecisionInteger(value);
        }
        else
        {
            writer.WriteString(value);
        }
    }
}
