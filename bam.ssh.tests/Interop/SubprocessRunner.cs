using System.Diagnostics;
using System.Text;

namespace Bam.Ssh.Tests.Interop
{
    /// <summary>
    /// Runs a subprocess with an argument list (no shell), captures its output, and enforces a hard timeout —
    /// a killed-on-timeout process can never stall the suite.
    /// </summary>
    internal static class SubprocessRunner
    {
        /// <summary>
        /// Runs the specified executable to completion or until the timeout elapses, capturing output.
        /// </summary>
        /// <param name="fileName">The absolute path of the executable to run.</param>
        /// <param name="arguments">The argument list, passed without shell interpretation.</param>
        /// <param name="timeout">The hard timeout after which the process is killed.</param>
        /// <returns>The captured <see cref="SubprocessResult"/>.</returns>
        internal static SubprocessResult Run(string fileName, IEnumerable<string> arguments, TimeSpan timeout)
        {
            ProcessStartInfo startInfo = new ProcessStartInfo
            {
                FileName = fileName,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                RedirectStandardInput = true,
                CreateNoWindow = true
            };
            foreach (string argument in arguments)
            {
                startInfo.ArgumentList.Add(argument);
            }

            using Process process = new Process { StartInfo = startInfo };
            StringBuilder standardOutput = new StringBuilder();
            StringBuilder standardError = new StringBuilder();
            process.OutputDataReceived += (sender, e) => { if (e.Data != null) { lock (standardOutput) { standardOutput.AppendLine(e.Data); } } };
            process.ErrorDataReceived += (sender, e) => { if (e.Data != null) { lock (standardError) { standardError.AppendLine(e.Data); } } };

            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            process.StandardInput.Close();

            bool exited = process.WaitForExit((int)timeout.TotalMilliseconds);
            if (!exited)
            {
                try
                {
                    process.Kill(entireProcessTree: true);
                }
                catch (InvalidOperationException)
                {
                    // The process exited between the timeout check and the kill.
                }
                process.WaitForExit();
                return new SubprocessResult
                {
                    ExitCode = -1,
                    TimedOut = true,
                    StandardOutput = ReadBuffer(standardOutput),
                    StandardError = ReadBuffer(standardError)
                };
            }

            // A final synchronous wait flushes the async output readers.
            process.WaitForExit();
            return new SubprocessResult
            {
                ExitCode = process.ExitCode,
                TimedOut = false,
                StandardOutput = ReadBuffer(standardOutput),
                StandardError = ReadBuffer(standardError)
            };
        }

        private static string ReadBuffer(StringBuilder buffer)
        {
            lock (buffer)
            {
                return buffer.ToString();
            }
        }
    }
}
