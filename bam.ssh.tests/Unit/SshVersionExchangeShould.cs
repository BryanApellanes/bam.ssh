using System.Text;
using Bam.Ssh.Transport;
using Bam.Test;

namespace Bam.Ssh.Tests.Unit;

[UnitTestMenu("SshVersionExchangeShould", Selector = "sve")]
public class SshVersionExchangeShould : UnitTestMenuContainer
{
    [UnitTest]
    public void ExchangeIdentificationsOverLoopback()
    {
        When.A<object>("completes the exchange and captures raw bytes without CRLF",
            new object(),
            (ignored) =>
            {
                (LoopbackDuplexStream client, LoopbackDuplexStream server) = LoopbackDuplexStream.CreatePair();
                SshTransportOptions clientOptions = new SshTransportOptions("Bam.Ssh_Client");
                SshTransportOptions serverOptions = new SshTransportOptions("Bam.Ssh_Server");
                SshVersionExchange clientExchange = new SshVersionExchange(client, clientOptions);
                SshVersionExchange serverExchange = new SshVersionExchange(server, serverOptions);

                Task<SshVersionExchangeResult> clientTask =
                    clientExchange.ExchangeAsync(clientOptions.CreateLocalIdentification()).AsTask();
                Task<SshVersionExchangeResult> serverTask =
                    serverExchange.ExchangeAsync(serverOptions.CreateLocalIdentification()).AsTask();
                Task.WhenAll(clientTask, serverTask).GetAwaiter().GetResult();

                SshVersionExchangeResult clientResult = clientTask.Result;
                bool[] results = new bool[4];
                results[0] = clientResult.Remote.SoftwareVersion == "Bam.Ssh_Server";
                results[1] = serverTask.Result.Remote.SoftwareVersion == "Bam.Ssh_Client";
                results[2] = Encoding.ASCII.GetString(clientResult.LocalRawBytes) == "SSH-2.0-Bam.Ssh_Client";
                results[3] = Encoding.ASCII.GetString(clientResult.RemoteRawBytes) == "SSH-2.0-Bam.Ssh_Server";
                return results;
            })
        .TheTest
        .ShouldPass(because =>
        {
            bool[] results = (bool[])because.Result;
            because.ItsTrue("the client saw the server's software version", results[0]);
            because.ItsTrue("the server saw the client's software version", results[1]);
            because.ItsTrue("local raw bytes exclude CRLF", results[2]);
            because.ItsTrue("remote raw bytes exclude CRLF", results[3]);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void TolerateBannerLinesBeforeIdentification()
    {
        When.A<object>("skips banner lines the server sends before its identification",
            new object(),
            (ignored) =>
            {
                (LoopbackDuplexStream client, LoopbackDuplexStream server) = LoopbackDuplexStream.CreatePair();
                SshTransportOptions options = new SshTransportOptions("Bam.Ssh_Client");

                byte[] banner = Encoding.ASCII.GetBytes("Authorized access only.\r\nContact admin@example.com\r\nSSH-2.0-ServerImpl_2.1\r\n");
                server.Output.WriteAsync(banner).AsTask().GetAwaiter().GetResult();
                server.Output.FlushAsync().AsTask().GetAwaiter().GetResult();

                SshVersionExchange clientExchange = new SshVersionExchange(client, options);
                SshVersionExchangeResult result =
                    clientExchange.ExchangeAsync(options.CreateLocalIdentification()).AsTask().GetAwaiter().GetResult();
                return result.Remote.SoftwareVersion == "ServerImpl_2.1";
            })
        .TheTest
        .ShouldPass(because =>
        {
            because.ItsTrue("the identification after two banner lines was found", (bool)because.Result);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RejectTooManyBannerLines()
    {
        When.A<object>("throws when the banner cap is exceeded",
            new object(),
            (ignored) =>
            {
                (LoopbackDuplexStream client, LoopbackDuplexStream server) = LoopbackDuplexStream.CreatePair();
                SshTransportOptions options = new SshTransportOptions("Bam.Ssh_Client", maxBannerLines: 3);

                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < 5; i++)
                {
                    builder.Append("banner line\r\n");
                }
                server.Output.WriteAsync(Encoding.ASCII.GetBytes(builder.ToString())).AsTask().GetAwaiter().GetResult();
                server.Output.FlushAsync().AsTask().GetAwaiter().GetResult();

                SshVersionExchange clientExchange = new SshVersionExchange(client, options);
                try
                {
                    clientExchange.ExchangeAsync(options.CreateLocalIdentification()).AsTask().GetAwaiter().GetResult();
                    return false;
                }
                catch (SshTransportException exception)
                {
                    return exception.Reason == SshDisconnectReason.ProtocolError;
                }
            })
        .TheTest
        .ShouldPass(because =>
        {
            because.ItsTrue("exceeding the banner cap throws ProtocolError", (bool)because.Result);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RejectUnsupportedProtocolVersion()
    {
        When.A<object>("throws when the peer advertises SSH 1.5",
            new object(),
            (ignored) =>
            {
                (LoopbackDuplexStream client, LoopbackDuplexStream server) = LoopbackDuplexStream.CreatePair();
                SshTransportOptions options = new SshTransportOptions("Bam.Ssh_Client");
                server.Output.WriteAsync(Encoding.ASCII.GetBytes("SSH-1.5-OldServer\r\n")).AsTask().GetAwaiter().GetResult();
                server.Output.FlushAsync().AsTask().GetAwaiter().GetResult();

                SshVersionExchange clientExchange = new SshVersionExchange(client, options);
                try
                {
                    clientExchange.ExchangeAsync(options.CreateLocalIdentification()).AsTask().GetAwaiter().GetResult();
                    return false;
                }
                catch (SshTransportException exception)
                {
                    return exception.Reason == SshDisconnectReason.ProtocolVersionNotSupported;
                }
            })
        .TheTest
        .ShouldPass(because =>
        {
            because.ItsTrue("an unsupported version throws ProtocolVersionNotSupported", (bool)because.Result);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }
}
