using System.IO.Pipelines;
using Bam.Ssh.Transport;

namespace Bam.Ssh.Benchmarks;

/// <summary>
/// Benchmarks the packet layer hot path — framing (RFC 4253 §6 encode/decode) plus the negotiated cipher —
/// by round-tripping a payload through an in-process pipe: <see cref="SshPacketWriter.WriteAsync"/> frames and
/// seals it, <see cref="SshPacketReader.ReadAsync"/> authenticates and de-frames it. Run for the identity
/// cipher and each real cipher family so framing overhead and per-cipher cost are visible separately.
/// </summary>
public static class PacketLayerBenchmark
{
    private const int WarmupIterations = 2000;

    /// <summary>
    /// Runs the packet-layer scenarios and returns their results.
    /// </summary>
    /// <returns>One result per (cipher, payload size) combination.</returns>
    public static async Task<IReadOnlyList<BenchmarkResult>> RunAsync()
    {
        List<BenchmarkResult> results = new List<BenchmarkResult>();
        (string label, string cipher, string mac)[] configurations = new (string, string, string)[]
        {
            ("none", SshAlgorithmNames.None, SshAlgorithmNames.None),
            ("chacha20-poly1305", SshAlgorithmNames.ChaCha20Poly1305, SshAlgorithmNames.None),
            ("aes256-gcm", SshAlgorithmNames.Aes256Gcm, SshAlgorithmNames.None),
            ("aes256-ctr+hmac-sha2-256", SshAlgorithmNames.Aes256Ctr, SshAlgorithmNames.HmacSha2256),
        };
        int[] payloadSizes = new int[] { 4 * 1024, 32 * 1024 };

        foreach ((string label, string cipher, string mac) in configurations)
        {
            foreach (int payloadSize in payloadSizes)
            {
                results.Add(await RunOneAsync(label, cipher, mac, payloadSize).ConfigureAwait(false));
            }
        }
        return results;
    }

    private static async Task<BenchmarkResult> RunOneAsync(string label, string cipherName, string macName, int payloadSize)
    {
        ISshPacketCipher writeCipher = CreateCipher(cipherName, macName);
        ISshPacketCipher readCipher = CreateCipher(cipherName, macName);
        Pipe pipe = new Pipe();
        SshPacketWriter writer = new SshPacketWriter(pipe.Writer, writeCipher);
        SshPacketReader reader = new SshPacketReader(pipe.Reader, readCipher);
        byte[] payload = new byte[payloadSize];
        for (int i = 0; i < payload.Length; i++)
        {
            payload[i] = (byte)i;
        }

        int iterations = payloadSize <= 4 * 1024 ? 20000 : 8000;
        return await BenchmarkRunner.MeasureAsync(
            $"packet {label} {payloadSize / 1024} KiB",
            WarmupIterations,
            iterations,
            payloadSize,
            async () =>
            {
                await writer.WriteAsync(payload).ConfigureAwait(false);
                using SshIncomingPacket packet = await reader.ReadAsync().ConfigureAwait(false);
            }).ConfigureAwait(false);
    }

    private static ISshPacketCipher CreateCipher(string cipherName, string macName)
    {
        if (cipherName == SshAlgorithmNames.None)
        {
            return NonePacketCipher.Instance;
        }
        byte[] key = new byte[64];
        byte[] iv = new byte[64];
        byte[] integrityKey = new byte[64];
        for (int i = 0; i < 64; i++)
        {
            key[i] = (byte)(i + 1);
            iv[i] = (byte)(i + 65);
            integrityKey[i] = (byte)(i + 129);
        }
        return SshCipherFactory.Create(cipherName, macName, key, iv, integrityKey);
    }
}
