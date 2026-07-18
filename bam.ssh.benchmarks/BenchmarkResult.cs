namespace Bam.Ssh.Benchmarks;

/// <summary>
/// The measured outcome of one benchmark scenario: how many iterations ran, how many bytes they processed,
/// how long it took, and how much managed memory was allocated. Derived properties express the results as
/// throughput (MiB/s), latency (ns/iteration), and allocation pressure (bytes/iteration).
/// </summary>
public sealed class BenchmarkResult
{
    /// <summary>
    /// Initializes the result.
    /// </summary>
    /// <param name="name">The scenario name.</param>
    /// <param name="iterations">The number of measured iterations.</param>
    /// <param name="bytesProcessed">The total application bytes processed across all iterations.</param>
    /// <param name="elapsed">The measured wall-clock time.</param>
    /// <param name="allocatedBytes">The managed bytes allocated during the measured run.</param>
    /// <param name="gen0Collections">The number of gen-0 garbage collections during the measured run.</param>
    public BenchmarkResult(string name, long iterations, long bytesProcessed, TimeSpan elapsed, long allocatedBytes, int gen0Collections)
    {
        Name = name;
        Iterations = iterations;
        BytesProcessed = bytesProcessed;
        Elapsed = elapsed;
        AllocatedBytes = allocatedBytes;
        Gen0Collections = gen0Collections;
    }

    /// <summary>
    /// Gets the scenario name.
    /// </summary>
    public string Name { get; }

    /// <summary>
    /// Gets the number of measured iterations.
    /// </summary>
    public long Iterations { get; }

    /// <summary>
    /// Gets the total application bytes processed across all iterations.
    /// </summary>
    public long BytesProcessed { get; }

    /// <summary>
    /// Gets the measured wall-clock time.
    /// </summary>
    public TimeSpan Elapsed { get; }

    /// <summary>
    /// Gets the managed bytes allocated during the measured run.
    /// </summary>
    public long AllocatedBytes { get; }

    /// <summary>
    /// Gets the number of gen-0 garbage collections during the measured run.
    /// </summary>
    public int Gen0Collections { get; }

    /// <summary>
    /// Gets the mean latency per iteration in nanoseconds.
    /// </summary>
    public double NanosecondsPerIteration => Iterations == 0 ? 0 : Elapsed.TotalMilliseconds * 1_000_000.0 / Iterations;

    /// <summary>
    /// Gets the throughput in mebibytes per second (0 when the scenario processes no application bytes).
    /// </summary>
    public double MebibytesPerSecond => Elapsed.TotalSeconds <= 0 ? 0 : BytesProcessed / (1024.0 * 1024.0) / Elapsed.TotalSeconds;

    /// <summary>
    /// Gets the mean managed allocation per iteration in bytes.
    /// </summary>
    public double AllocatedBytesPerIteration => Iterations == 0 ? 0 : (double)AllocatedBytes / Iterations;
}
