using System.Net;
using Bam.Ssh.Authentication;
using Bam.Ssh.Client;
using Bam.Ssh.Connection;
using Bam.Ssh.Server;

namespace Bam.Ssh.Benchmarks;

/// <summary>
/// Benchmarks end-to-end channel throughput over the full production stack: a real <see cref="SshClient"/>
/// pushes bulk data through a session channel to a real <see cref="SshServer"/> subsystem that drains it, over
/// a TCP loopback connection with a real cipher. This is the realistic number — framing, encryption,
/// flow-control windows, and pipelines all in the path.
/// </summary>
public static class ChannelThroughputBenchmark
{
    private const string UserName = "bench";
    private const string Password = "bench-secret";
    private const int ChunkSize = 64 * 1024;

    /// <summary>
    /// Establishes one authenticated connection and measures pushing a fixed volume of bytes through a
    /// draining subsystem channel.
    /// </summary>
    /// <returns>The measured throughput result.</returns>
    public static async Task<BenchmarkResult> RunAsync()
    {
        Ed25519PrivateKey hostKey = new Ed25519PrivateKey(MakeSeed(0x11));
        await using SshServer server = new SshServer();
        server.AddHostKey(hostKey);
        server.UsePasswordAuthentication(new BenchPasswordAuthenticator());
        server.MapSubsystem("sink", DrainAsync);
        await server.StartAsync(new IPEndPoint(IPAddress.Loopback, 0)).ConfigureAwait(false);
        int port = server.ListenEndPoint!.Port;

        await using SshClient client = new SshClient(new SshClientOptions(AcceptAllHostKeyVerifier.Instance));
        await client.ConnectAsync("127.0.0.1", port).ConfigureAwait(false);
        await client.AuthenticateWithPasswordAsync(UserName, Password).ConfigureAwait(false);
        SshSessionChannel channel = await client.OpenSessionChannelAsync().ConfigureAwait(false);
        if (!await channel.SubsystemAsync("sink").ConfigureAwait(false))
        {
            throw new InvalidOperationException("The server refused the sink subsystem.");
        }

        byte[] chunk = new byte[ChunkSize];
        for (int i = 0; i < chunk.Length; i++)
        {
            chunk[i] = (byte)i;
        }

        // One measured bulk push; the warmup iteration inside MeasureAsync primes the JIT and flow windows.
        long totalBytes = 128L * 1024 * 1024;
        BenchmarkResult result = await BenchmarkRunner.MeasureAsync(
            "channel throughput (default: chacha20-poly1305)",
            warmupIterations: 1,
            iterations: 1,
            bytesPerIteration: totalBytes,
            async () =>
            {
                await PushAsync(channel, chunk, totalBytes).ConfigureAwait(false);
            }).ConfigureAwait(false);

        await channel.Channel.SendEofAsync().ConfigureAwait(false);
        await channel.Channel.CloseAsync().ConfigureAwait(false);
        return result;
    }

    private static async Task PushAsync(SshSessionChannel channel, byte[] chunk, long totalBytes)
    {
        long sent = 0;
        while (sent < totalBytes)
        {
            await channel.Channel.WriteAsync(chunk).ConfigureAwait(false);
            sent += chunk.Length;
        }
    }

    private static async Task DrainAsync(SshServerCommandContext context, CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[ChunkSize];
        while (await context.ReadAsync(buffer, cancellationToken).ConfigureAwait(false) > 0)
        {
        }
    }

    private static byte[] MakeSeed(byte fill)
    {
        byte[] seed = new byte[32];
        Array.Fill(seed, fill);
        return seed;
    }

    private sealed class BenchPasswordAuthenticator : ISshPasswordAuthenticator
    {
        public ValueTask<bool> AuthenticateAsync(string userName, string password, CancellationToken cancellationToken = default)
        {
            bool ok = string.Equals(userName, UserName, StringComparison.Ordinal)
                && string.Equals(password, Password, StringComparison.Ordinal);
            return ValueTask.FromResult(ok);
        }
    }
}
