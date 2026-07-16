using System.Text;
using Bam.Ssh.Client;
using Bam.Ssh.Transport;
using Bam.Test;

namespace Bam.Ssh.Tests.Unit;

/// <summary>
/// End-to-end proof of the high-level <see cref="SshClient"/> against a combined loopback server that
/// chains the production version/key-exchange/authentication/connection doubles: a single connect →
/// authenticate → execute sequence returns the command's output and exit code; a rejecting host-key
/// verifier aborts the connect before any credentials are sent; and running before authentication is a
/// state error.
/// </summary>
[UnitTestMenu("SshClientShould", Selector = "client")]
public class SshClientShould : UnitTestMenuContainer
{
    [UnitTest]
    public void ConnectAuthenticateAndRunACommand()
    {
        When.A<object>("connects, authenticates, and runs a command end to end", new object(), (ignored) =>
        {
            TestUserAuthServer authServer = new TestUserAuthServer { AcceptPassword = "s3cret" };
            TestConnectionServer connectionServer = new TestConnectionServer
            {
                StandardOutput = Encoding.UTF8.GetBytes("uid=0(root)"),
                StandardError = Encoding.UTF8.GetBytes("a warning"),
                SendExitStatus = true,
                ExitCode = 3,
                CloseAfterResponse = true
            };
            SshClientOptions options = new SshClientOptions(AcceptAllHostKeyVerifier.Instance);
            return ClientTestSupport.Run(options, authServer, connectionServer, async (client, stream) =>
            {
                await client.ConnectAsync(stream, "test-host", 22);
                await client.AuthenticateWithPasswordAsync("tester", "s3cret");
                SshCommandResult result = await client.ExecuteAsync("id");
                return new CommandOutcome(result.StandardOutputText, result.StandardErrorText, result.ExitCode);
            });
        })
        .TheTest
        .ShouldPass(because =>
        {
            CommandOutcome outcome = (CommandOutcome)because.Result;
            because.ItsTrue("stdout was captured", outcome.StandardOutput == "uid=0(root)");
            because.ItsTrue("stderr was captured", outcome.StandardError == "a warning");
            because.ItsTrue("the exit code was reported", outcome.ExitCode == 3);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void AbortWhenTheHostKeyIsRejected()
    {
        When.A<object>("aborts the connect when the host key is rejected", new object(), (ignored) =>
        {
            TestUserAuthServer authServer = new TestUserAuthServer { AcceptPassword = "s3cret" };
            TestConnectionServer connectionServer = new TestConnectionServer();
            ISshHostKeyVerifier rejectAll = new CallbackHostKeyVerifier((context, token) => ValueTask.FromResult(false));
            SshClientOptions options = new SshClientOptions(rejectAll);
            return ClientTestSupport.Run(options, authServer, connectionServer, async (client, stream) =>
            {
                try
                {
                    await client.ConnectAsync(stream, "test-host", 22);
                    return false;
                }
                catch (SshHostKeyRejectedException)
                {
                    return true;
                }
            });
        })
        .TheTest
        .ShouldPass(because => because.ItsTrue("ConnectAsync threw SshHostKeyRejectedException", (bool)because.Result))
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RefuseToRunBeforeAuthentication()
    {
        When.A<object>("refuses to execute before authentication", new object(), (ignored) =>
        {
            TestUserAuthServer authServer = new TestUserAuthServer { AcceptPassword = "s3cret" };
            TestConnectionServer connectionServer = new TestConnectionServer();
            SshClientOptions options = new SshClientOptions(AcceptAllHostKeyVerifier.Instance);
            return ClientTestSupport.Run(options, authServer, connectionServer, async (client, stream) =>
            {
                await client.ConnectAsync(stream, "test-host", 22);
                try
                {
                    await client.ExecuteAsync("id");
                    return false;
                }
                catch (SshConnectionStateException)
                {
                    return true;
                }
            });
        })
        .TheTest
        .ShouldPass(because => because.ItsTrue("ExecuteAsync before auth threw SshConnectionStateException", (bool)because.Result))
        .SoBeHappy()
        .UnlessItFailed();
    }

    private sealed class CommandOutcome
    {
        public CommandOutcome(string standardOutput, string standardError, int? exitCode)
        {
            StandardOutput = standardOutput;
            StandardError = standardError;
            ExitCode = exitCode;
        }

        public string StandardOutput { get; }

        public string StandardError { get; }

        public int? ExitCode { get; }
    }
}
