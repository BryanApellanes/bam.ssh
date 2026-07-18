using System.Diagnostics;

namespace Bam.Ssh.Benchmarks;

/// <summary>
/// A minimal, dependency-free benchmark harness — no BenchmarkDotNet, matching the stack's zero-dependency,
/// reflection-free, Native-AOT ethos. It runs a warmup, forces a clean GC baseline, then times a fixed number
/// of iterations while measuring managed allocations via <see cref="GC.GetTotalAllocatedBytes(bool)"/> (which
/// captures allocations on continuation threads for the async scenarios).
/// </summary>
public static class BenchmarkRunner
{
    /// <summary>
    /// Measures a synchronous iteration.
    /// </summary>
    /// <param name="name">The scenario name.</param>
    /// <param name="warmupIterations">Iterations run (and discarded) before measurement.</param>
    /// <param name="iterations">Measured iterations.</param>
    /// <param name="bytesPerIteration">Application bytes each iteration processes (for throughput).</param>
    /// <param name="iteration">The work to measure.</param>
    /// <returns>The measured result.</returns>
    public static BenchmarkResult Measure(string name, int warmupIterations, int iterations, long bytesPerIteration, Action iteration)
    {
        ArgumentNullException.ThrowIfNull(iteration);
        for (int i = 0; i < warmupIterations; i++)
        {
            iteration();
        }

        Collect();
        long allocatedBefore = GC.GetTotalAllocatedBytes(precise: true);
        int gen0Before = GC.CollectionCount(0);
        Stopwatch stopwatch = Stopwatch.StartNew();
        for (int i = 0; i < iterations; i++)
        {
            iteration();
        }
        stopwatch.Stop();
        long allocated = GC.GetTotalAllocatedBytes(precise: true) - allocatedBefore;
        int gen0 = GC.CollectionCount(0) - gen0Before;
        return new BenchmarkResult(name, iterations, bytesPerIteration * iterations, stopwatch.Elapsed, allocated, gen0);
    }

    /// <summary>
    /// Measures an asynchronous iteration (each iteration is awaited to completion before the next).
    /// </summary>
    /// <param name="name">The scenario name.</param>
    /// <param name="warmupIterations">Iterations run (and discarded) before measurement.</param>
    /// <param name="iterations">Measured iterations.</param>
    /// <param name="bytesPerIteration">Application bytes each iteration processes (for throughput).</param>
    /// <param name="iteration">The work to measure.</param>
    /// <returns>The measured result.</returns>
    public static async Task<BenchmarkResult> MeasureAsync(string name, int warmupIterations, int iterations, long bytesPerIteration, Func<Task> iteration)
    {
        ArgumentNullException.ThrowIfNull(iteration);
        for (int i = 0; i < warmupIterations; i++)
        {
            await iteration().ConfigureAwait(false);
        }

        Collect();
        long allocatedBefore = GC.GetTotalAllocatedBytes(precise: true);
        int gen0Before = GC.CollectionCount(0);
        Stopwatch stopwatch = Stopwatch.StartNew();
        for (int i = 0; i < iterations; i++)
        {
            await iteration().ConfigureAwait(false);
        }
        stopwatch.Stop();
        long allocated = GC.GetTotalAllocatedBytes(precise: true) - allocatedBefore;
        int gen0 = GC.CollectionCount(0) - gen0Before;
        return new BenchmarkResult(name, iterations, bytesPerIteration * iterations, stopwatch.Elapsed, allocated, gen0);
    }

    private static void Collect()
    {
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
    }
}
