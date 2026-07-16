using System.Text;
using Bam.Ssh.Authentication;
using Bam.Ssh.Client;
using Bam.Ssh.Connection;
using Bam.Ssh.Server;
using Bam.Ssh.Transport;
using Bam.Test;

namespace Bam.Ssh.Tests.Unit;

/// <summary>
/// End-to-end proof of the high-level <see cref="SshServer"/> against the production <see cref="SshClient"/>
/// over a loopback transport: a client connects, authenticates by password or public key, and runs a mapped
/// command whose stdout/stderr/exit-status flow back; wrong credentials are refused; an unmapped command and
/// a non-session channel are rejected; and a subsystem streams bidirectionally. This is the crown-jewel test
/// that both real endpoints of the whole stack interoperate.
/// </summary>
[UnitTestMenu("SshServerShould", Selector = "server")]
public class SshServerShould : UnitTestMenuContainer
{
    [UnitTest]
    public void AuthenticateWithPasswordAndRunACommand()
    {
        When.A<object>("serves a password-authenticated exec end to end", new object(), (ignored) =>
        {
            return ServerTestSupport.Run(server =>
            {
                server.AddHostKey(new Ed25519PrivateKey(ServerTestSupport.MakeSeed(0x11)));
                server.UsePasswordAuthentication(new FixedPasswordAuthenticator("tester", "s3cret"));
                server.MapExec(async (context, token) =>
                {
                    await context.WriteAsync("uid=0(root)", token);
                    await context.WriteErrorAsync("a warning", token);
                    await context.ExitAsync(3, token);
                });
            },
            async (client, stream) =>
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
            because.ItsTrue("stdout flowed from the mapped handler", outcome.StandardOutput == "uid=0(root)");
            because.ItsTrue("stderr flowed from the mapped handler", outcome.StandardError == "a warning");
            because.ItsTrue("the handler's exit code reached the client", outcome.ExitCode == 3);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void AuthenticateWithAPublicKey()
    {
        When.A<object>("serves a publickey-authenticated exec end to end", new object(), (ignored) =>
        {
            Ed25519PrivateKey clientKey = new Ed25519PrivateKey(ServerTestSupport.MakeSeed(0x22));
            return ServerTestSupport.Run(server =>
            {
                server.AddHostKey(new Ed25519PrivateKey(ServerTestSupport.MakeSeed(0x11)));
                server.UsePublicKeyAuthentication(new FixedPublicKeyAuthenticator(clientKey.PublicKeyBlob));
                server.MapExec(async (context, token) =>
                {
                    await context.WriteAsync($"hello {context.UserName}", token);
                    await context.ExitAsync(0, token);
                });
            },
            async (client, stream) =>
            {
                await client.ConnectAsync(stream, "test-host", 22);
                await client.AuthenticateWithPublicKeyAsync("tester", clientKey);
                SshCommandResult result = await client.ExecuteAsync("whoami");
                return new CommandOutcome(result.StandardOutputText, result.StandardErrorText, result.ExitCode);
            });
        })
        .TheTest
        .ShouldPass(because =>
        {
            CommandOutcome outcome = (CommandOutcome)because.Result;
            because.ItsTrue("the authenticated user reached the handler", outcome.StandardOutput == "hello tester");
            because.ItsTrue("the command completed with exit 0", outcome.ExitCode == 0);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RejectAnIncorrectPassword()
    {
        When.A<object>("refuses an incorrect password", new object(), (ignored) =>
        {
            return ServerTestSupport.Run(server =>
            {
                server.AddHostKey(new Ed25519PrivateKey(ServerTestSupport.MakeSeed(0x11)));
                server.UsePasswordAuthentication(new FixedPasswordAuthenticator("tester", "s3cret"));
                server.MapExec((context, token) => Task.CompletedTask);
            },
            async (client, stream) =>
            {
                await client.ConnectAsync(stream, "test-host", 22);
                try
                {
                    await client.AuthenticateWithPasswordAsync("tester", "wrong");
                    return false;
                }
                catch (SshAuthenticationException)
                {
                    return true;
                }
            });
        })
        .TheTest
        .ShouldPass(because => because.ItsTrue("authentication threw SshAuthenticationException", (bool)because.Result))
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RejectAnUnauthorizedPublicKey()
    {
        When.A<object>("refuses a public key the policy does not authorize", new object(), (ignored) =>
        {
            Ed25519PrivateKey authorizedKey = new Ed25519PrivateKey(ServerTestSupport.MakeSeed(0x22));
            Ed25519PrivateKey unauthorizedKey = new Ed25519PrivateKey(ServerTestSupport.MakeSeed(0x33));
            return ServerTestSupport.Run(server =>
            {
                server.AddHostKey(new Ed25519PrivateKey(ServerTestSupport.MakeSeed(0x11)));
                server.UsePublicKeyAuthentication(new FixedPublicKeyAuthenticator(authorizedKey.PublicKeyBlob));
                server.MapExec((context, token) => Task.CompletedTask);
            },
            async (client, stream) =>
            {
                await client.ConnectAsync(stream, "test-host", 22);
                try
                {
                    await client.AuthenticateWithPublicKeyAsync("tester", unauthorizedKey);
                    return false;
                }
                catch (SshAuthenticationException)
                {
                    return true;
                }
            });
        })
        .TheTest
        .ShouldPass(because => because.ItsTrue("authentication threw SshAuthenticationException", (bool)because.Result))
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RefuseAnUnmappedCommand()
    {
        When.A<object>("refuses an exec when no exec handler is mapped", new object(), (ignored) =>
        {
            return ServerTestSupport.Run(server =>
            {
                server.AddHostKey(new Ed25519PrivateKey(ServerTestSupport.MakeSeed(0x11)));
                server.UsePasswordAuthentication(new FixedPasswordAuthenticator("tester", "s3cret"));
                server.MapShell((context, token) => Task.CompletedTask);
            },
            async (client, stream) =>
            {
                await client.ConnectAsync(stream, "test-host", 22);
                await client.AuthenticateWithPasswordAsync("tester", "s3cret");
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
        .ShouldPass(because => because.ItsTrue("the unmapped exec was refused", (bool)because.Result))
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RejectANonSessionChannel()
    {
        When.A<object>("rejects a channel type it does not serve", new object(), (ignored) =>
        {
            return ServerTestSupport.Run(server =>
            {
                server.AddHostKey(new Ed25519PrivateKey(ServerTestSupport.MakeSeed(0x11)));
                server.UsePasswordAuthentication(new FixedPasswordAuthenticator("tester", "s3cret"));
                server.MapExec((context, token) => Task.CompletedTask);
            },
            async (client, stream) =>
            {
                await client.ConnectAsync(stream, "test-host", 22);
                await client.AuthenticateWithPasswordAsync("tester", "s3cret");
                SshChannelOpenParameters parameters = new SshChannelOpenParameters("direct-tcpip", 1 << 15, 1 << 15);
                try
                {
                    await client.Connection.OpenChannelAsync(parameters);
                    return false;
                }
                catch (SshChannelException)
                {
                    return true;
                }
            });
        })
        .TheTest
        .ShouldPass(because => because.ItsTrue("the non-session open was rejected", (bool)because.Result))
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void StreamThroughASubsystem()
    {
        When.A<object>("streams standard input back out through a subsystem", new object(), (ignored) =>
        {
            return ServerTestSupport.Run(server =>
            {
                server.AddHostKey(new Ed25519PrivateKey(ServerTestSupport.MakeSeed(0x11)));
                server.UsePasswordAuthentication(new FixedPasswordAuthenticator("tester", "s3cret"));
                server.MapSubsystem("echo", async (context, token) =>
                {
                    byte[] rented = new byte[1024];
                    while (true)
                    {
                        int count = await context.ReadAsync(rented, token);
                        if (count == 0)
                        {
                            break;
                        }
                        await context.WriteAsync(rented.AsMemory(0, count), token);
                    }
                    await context.ExitAsync(0, token);
                });
            },
            async (client, stream) =>
            {
                await client.ConnectAsync(stream, "test-host", 22);
                await client.AuthenticateWithPasswordAsync("tester", "s3cret");
                SshSessionChannel channel = await client.OpenSessionChannelAsync();
                bool started = await channel.SubsystemAsync("echo");
                await channel.Channel.WriteAsync(Encoding.UTF8.GetBytes("ping-pong"));
                await channel.Channel.SendEofAsync();
                byte[] echoed = await ServerTestSupport.ReadAllAsync(channel.Channel.ReadAsync);
                return new SubsystemOutcome(started, Encoding.UTF8.GetString(echoed));
            });
        })
        .TheTest
        .ShouldPass(because =>
        {
            SubsystemOutcome outcome = (SubsystemOutcome)because.Result;
            because.ItsTrue("the server started the subsystem", outcome.Started);
            because.ItsTrue("the subsystem echoed the input", outcome.Echoed == "ping-pong");
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RequireAHostKeyBeforeServing()
    {
        When.A<object>("refuses to accept a connection without a host key", new object(), (ignored) =>
        {
            (LoopbackDuplexStream clientStream, LoopbackDuplexStream serverStream) = LoopbackDuplexStream.CreatePair();
            SshServer server = new SshServer();
            server.UsePasswordAuthentication(new FixedPasswordAuthenticator("tester", "s3cret"));
            try
            {
                server.AcceptAsync(serverStream).AsTask().GetAwaiter().GetResult();
                return false;
            }
            catch (SshServerException)
            {
                return true;
            }
            finally
            {
                server.DisposeAsync().AsTask().GetAwaiter().GetResult();
                clientStream.DisposeAsync().AsTask().GetAwaiter().GetResult();
            }
        })
        .TheTest
        .ShouldPass(because => because.ItsTrue("AcceptAsync threw SshServerException", (bool)because.Result))
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

    private sealed class SubsystemOutcome
    {
        public SubsystemOutcome(bool started, string echoed)
        {
            Started = started;
            Echoed = echoed;
        }

        public bool Started { get; }

        public string Echoed { get; }
    }
}
