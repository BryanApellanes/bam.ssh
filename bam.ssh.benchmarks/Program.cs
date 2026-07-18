using System.Globalization;

namespace Bam.Ssh.Benchmarks;

/// <summary>
/// Entry point for the bam.ssh benchmark suite. Runs the packet-layer (framing + cipher) and end-to-end
/// channel-throughput scenarios and prints a table of throughput, latency, and per-iteration allocation. Run
/// in Release for meaningful numbers: <c>dotnet run --project bam.ssh.benchmarks -c Release</c>.
/// </summary>
public static class Program
{
    /// <summary>
    /// Runs the benchmark suite.
    /// </summary>
    /// <param name="args">Optional scenario filter: <c>packet</c> or <c>channel</c> runs only that group.</param>
    public static async Task Main(string[] args)
    {
        string filter = args.Length > 0 ? args[0].ToLowerInvariant() : "all";
        List<BenchmarkResult> results = new List<BenchmarkResult>();

        if (filter is "all" or "packet")
        {
            results.AddRange(await PacketLayerBenchmark.RunAsync().ConfigureAwait(false));
        }
        if (filter is "all" or "channel")
        {
            results.Add(await ChannelThroughputBenchmark.RunAsync().ConfigureAwait(false));
        }

        PrintTable(results);
    }

    private static void PrintTable(IReadOnlyList<BenchmarkResult> results)
    {
        Console.WriteLine();
        Console.WriteLine($"{"scenario",-40} {"MiB/s",12} {"ns/op",14} {"bytes/op",14} {"gen0",6}");
        Console.WriteLine(new string('-', 90));
        foreach (BenchmarkResult result in results)
        {
            Console.WriteLine(string.Format(
                CultureInfo.InvariantCulture,
                "{0,-40} {1,12:N1} {2,14:N1} {3,14:N1} {4,6}",
                result.Name,
                result.MebibytesPerSecond,
                result.NanosecondsPerIteration,
                result.AllocatedBytesPerIteration,
                result.Gen0Collections));
        }
        Console.WriteLine();
    }
}
