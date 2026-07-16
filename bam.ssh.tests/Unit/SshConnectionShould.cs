using System.Text;
using Bam.Ssh.Connection;
using Bam.Test;

namespace Bam.Ssh.Tests.Unit;

/// <summary>
/// End-to-end proof of the RFC 4254 connection protocol over a fully keyed loopback pair against a test
/// server that uses the production wire primitives: session channels open (and rejections surface),
/// commands run with data and exit status flowing back, stderr stays separate, requests can be refused,
/// flow control both blocks a large writer and replenishes a draining reader, half-close ends the stream,
/// a mid-stream re-key preserves the session and keeps the channel usable, writing to a closed channel
/// faults, and an unknown global request is answered with REQUEST_FAILURE.
/// </summary>
[UnitTestMenu("SshConnectionShould", Selector = "conn")]
public class SshConnectionShould : UnitTestMenuContainer
{
    private static readonly SshConnectionOptions FastRekeyDisabled =
        new SshConnectionOptions(rekeyBytes: long.MaxValue, rekeyInterval: TimeSpan.FromDays(1));

    [UnitTest]
    public void OpenASessionChannel()
    {
        When.A<object>("opens a session channel", new object(), (ignored) =>
        {
            TestConnectionServer server = new TestConnectionServer();
            return ConnectionTestSupport.Run(FastRekeyDisabled, server, async (connection, srv) =>
            {
                SshSessionChannel channel = await connection.OpenSessionChannelAsync();
                return channel.Channel.LocalId == 0 && channel.Channel.RemoteId == 0;
            });
        })
        .TheTest
        .ShouldPass(because => because.ItsTrue("the session channel opened with the expected ids", (bool)because.Result))
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void SurfaceARejectedChannelOpen()
    {
        When.A<object>("surfaces a channel-open rejection as an exception", new object(), (ignored) =>
        {
            TestConnectionServer server = new TestConnectionServer { RejectOpen = true };
            return ConnectionTestSupport.Run(FastRekeyDisabled, server, async (connection, srv) =>
            {
                try
                {
                    await connection.OpenSessionChannelAsync();
                    return false;
                }
                catch (SshChannelException)
                {
                    return true;
                }
            });
        })
        .TheTest
        .ShouldPass(because => because.ItsTrue("OpenSessionChannelAsync threw SshChannelException", (bool)because.Result))
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RunACommandAndReceiveDataAndExitStatus()
    {
        When.A<object>("runs a command and receives its output and exit status", new object(), (ignored) =>
        {
            TestConnectionServer server = new TestConnectionServer
            {
                StandardOutput = Encoding.UTF8.GetBytes("hello from the server"),
                SendExitStatus = true,
                ExitCode = 7,
                CloseAfterResponse = true
            };
            return ConnectionTestSupport.Run(FastRekeyDisabled, server, async (connection, srv) =>
            {
                SshSessionChannel channel = await connection.OpenSessionChannelAsync();
                uint observedExit = uint.MaxValue;
                channel.ExitStatusReceived += (s, e) => observedExit = e.ExitCode;
                bool accepted = await channel.ExecAsync("run");
                string output = Encoding.UTF8.GetString(await ReadAllAsync(channel));
                return new ExecOutcome(accepted, output, observedExit);
            });
        })
        .TheTest
        .ShouldPass(because =>
        {
            ExecOutcome outcome = (ExecOutcome)because.Result;
            because.ItsTrue("the exec request was accepted", outcome.Accepted);
            because.ItsTrue("the command output round-tripped", outcome.Output == "hello from the server");
            because.ItsTrue("the exit status was reported", outcome.ExitCode == 7);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void DeliverExtendedDataOnASeparateStream()
    {
        When.A<object>("delivers stderr on the extended-data stream", new object(), (ignored) =>
        {
            TestConnectionServer server = new TestConnectionServer
            {
                StandardError = Encoding.UTF8.GetBytes("an error occurred"),
                CloseAfterResponse = true
            };
            return ConnectionTestSupport.Run(FastRekeyDisabled, server, async (connection, srv) =>
            {
                SshSessionChannel channel = await connection.OpenSessionChannelAsync();
                await channel.ExecAsync("run");
                string stderr = Encoding.UTF8.GetString(await ReadAllExtendedAsync(channel));
                byte[] stdout = await ReadAllAsync(channel);
                return new ExtendedOutcome(stderr, stdout.Length);
            });
        })
        .TheTest
        .ShouldPass(because =>
        {
            ExtendedOutcome outcome = (ExtendedOutcome)because.Result;
            because.ItsTrue("stderr arrived on the extended stream", outcome.StandardError == "an error occurred");
            because.ItsTrue("the stdout stream was empty", outcome.StandardOutputLength == 0);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void ReportARefusedRequest()
    {
        When.A<object>("reports a refused channel request", new object(), (ignored) =>
        {
            TestConnectionServer server = new TestConnectionServer { RejectRequest = true };
            return ConnectionTestSupport.Run(FastRekeyDisabled, server, async (connection, srv) =>
            {
                SshSessionChannel channel = await connection.OpenSessionChannelAsync();
                return await channel.ExecAsync("run");
            });
        })
        .TheTest
        .ShouldPass(because => because.ItsFalse("the refused exec returned false", (bool)because.Result))
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void HonourFlowControlWhenWritingMoreThanOneWindow()
    {
        When.A<object>("chunks and flow-controls a write larger than the peer window", new object(), (ignored) =>
        {
            byte[] payload = CreatePattern(16 * 1024);
            TestConnectionServer server = new TestConnectionServer
            {
                AdvertisedWindow = 4096,
                AdvertisedMaxPacket = 1024
            };
            return ConnectionTestSupport.Run(FastRekeyDisabled, server, async (connection, srv) =>
            {
                SshSessionChannel channel = await connection.OpenSessionChannelAsync();
                await channel.Channel.WriteAsync(payload);
                await channel.Channel.SendEofAsync();
                bool complete = await WaitForAsync(() => srv.ReceivedData.Count == payload.Length);
                bool matches = complete && srv.ReceivedData.ToArray().AsSpan().SequenceEqual(payload);
                return matches;
            });
        })
        .TheTest
        .ShouldPass(because => because.ItsTrue("the whole payload arrived intact despite a small window", (bool)because.Result))
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void ReplenishTheReceiveWindowWhileDraining()
    {
        When.A<object>("keeps receiving a payload larger than the local window as it drains", new object(), (ignored) =>
        {
            byte[] payload = CreatePattern(16 * 1024);
            SshConnectionOptions smallWindow = new SshConnectionOptions(
                initialWindowSize: 4096,
                maximumPacketSize: 1024,
                rekeyBytes: long.MaxValue,
                rekeyInterval: TimeSpan.FromDays(1));
            TestConnectionServer server = new TestConnectionServer
            {
                StandardOutput = payload,
                CloseAfterResponse = true
            };
            return ConnectionTestSupport.Run(smallWindow, server, async (connection, srv) =>
            {
                SshSessionChannel channel = await connection.OpenSessionChannelAsync();
                await channel.ExecAsync("run");
                byte[] output = await ReadAllAsync(channel);
                return output.AsSpan().SequenceEqual(payload);
            });
        })
        .TheTest
        .ShouldPass(because => because.ItsTrue("the full payload arrived across many window adjustments", (bool)because.Result))
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void EndTheStreamOnHalfClose()
    {
        When.A<object>("ends the read stream when the peer sends EOF and CLOSE", new object(), (ignored) =>
        {
            TestConnectionServer server = new TestConnectionServer { CloseAfterResponse = true };
            return ConnectionTestSupport.Run(FastRekeyDisabled, server, async (connection, srv) =>
            {
                SshSessionChannel channel = await connection.OpenSessionChannelAsync();
                await channel.ExecAsync("run");
                byte[] buffer = new byte[16];
                int read = await channel.Channel.ReadAsync(buffer);
                await channel.Channel.CloseAsync();
                return read == 0;
            });
        })
        .TheTest
        .ShouldPass(because => because.ItsTrue("the read returned end-of-stream", (bool)because.Result))
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RekeyAndKeepTheChannelUsable()
    {
        When.A<object>("re-keys mid-session and keeps the channel usable", new object(), (ignored) =>
        {
            byte[] payload = Encoding.UTF8.GetBytes("data sent after the re-key completes");
            TestConnectionServer server = new TestConnectionServer();
            return ConnectionTestSupport.Run(FastRekeyDisabled, server, async (connection, srv) =>
            {
                SshSessionChannel channel = await connection.OpenSessionChannelAsync();
                await connection.RekeyAsync();
                await channel.Channel.WriteAsync(payload);
                await channel.Channel.SendEofAsync();
                bool complete = await WaitForAsync(() => srv.ReceivedData.Count == payload.Length);
                return complete && srv.ReceivedData.ToArray().AsSpan().SequenceEqual(payload);
            });
        })
        .TheTest
        .ShouldPass(because => because.ItsTrue("application data flowed intact after re-keying", (bool)because.Result))
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void FaultWritesToAClosedChannel()
    {
        When.A<object>("faults a write to a closed channel", new object(), (ignored) =>
        {
            TestConnectionServer server = new TestConnectionServer();
            return ConnectionTestSupport.Run(FastRekeyDisabled, server, async (connection, srv) =>
            {
                SshSessionChannel channel = await connection.OpenSessionChannelAsync();
                await channel.Channel.CloseAsync();
                try
                {
                    await channel.Channel.WriteAsync(new byte[] { 1, 2, 3 });
                    return false;
                }
                catch (SshChannelException)
                {
                    return true;
                }
            });
        })
        .TheTest
        .ShouldPass(because => because.ItsTrue("writing after CLOSE threw SshChannelException", (bool)because.Result))
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RejectAnUnknownGlobalRequest()
    {
        When.A<object>("answers an unknown global request with REQUEST_FAILURE", new object(), (ignored) =>
        {
            TestConnectionServer server = new TestConnectionServer();
            return ConnectionTestSupport.Run(FastRekeyDisabled, server, async (connection, srv) =>
            {
                // The server probes the client, which must reply FAILURE to a request it does not know.
                bool clientAccepted = await srv.ProbeGlobalRequestAsync(CancellationToken.None);
                // The client also asks the server, exercising the reply-completion path.
                bool serverAccepted = await connection.SendGlobalRequestAsync("no-such@bam.ssh", true, ReadOnlyMemory<byte>.Empty);
                return !clientAccepted && !serverAccepted;
            });
        })
        .TheTest
        .ShouldPass(because => because.ItsTrue("both directions reported the request was refused", (bool)because.Result))
        .SoBeHappy()
        .UnlessItFailed();
    }

    private static async Task<byte[]> ReadAllAsync(SshSessionChannel channel)
    {
        return await ReadStreamAsync((buffer, token) => channel.Channel.ReadAsync(buffer, token));
    }

    private static async Task<byte[]> ReadAllExtendedAsync(SshSessionChannel channel)
    {
        return await ReadStreamAsync((buffer, token) => channel.Channel.ReadExtendedAsync(buffer, token));
    }

    private static async Task<byte[]> ReadStreamAsync(Func<Memory<byte>, CancellationToken, ValueTask<int>> read)
    {
        using CancellationTokenSource timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        List<byte> collected = new List<byte>();
        byte[] buffer = new byte[4096];
        while (true)
        {
            int count = await read(buffer, timeout.Token).ConfigureAwait(false);
            if (count == 0)
            {
                return collected.ToArray();
            }
            collected.AddRange(buffer.AsSpan(0, count).ToArray());
        }
    }

    private static async Task<bool> WaitForAsync(Func<bool> condition)
    {
        for (int attempt = 0; attempt < 300; attempt++)
        {
            if (condition())
            {
                return true;
            }
            await Task.Delay(50).ConfigureAwait(false);
        }
        return condition();
    }

    private static byte[] CreatePattern(int length)
    {
        byte[] data = new byte[length];
        for (int i = 0; i < length; i++)
        {
            data[i] = (byte)(i * 31 + 7);
        }
        return data;
    }

    private sealed class ExecOutcome
    {
        public ExecOutcome(bool accepted, string output, uint exitCode)
        {
            Accepted = accepted;
            Output = output;
            ExitCode = exitCode;
        }

        public bool Accepted { get; }

        public string Output { get; }

        public uint ExitCode { get; }
    }

    private sealed class ExtendedOutcome
    {
        public ExtendedOutcome(string standardError, int standardOutputLength)
        {
            StandardError = standardError;
            StandardOutputLength = standardOutputLength;
        }

        public string StandardError { get; }

        public int StandardOutputLength { get; }
    }
}
