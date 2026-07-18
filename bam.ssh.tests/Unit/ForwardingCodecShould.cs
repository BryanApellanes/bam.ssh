using Bam.Ssh.Forwarding;
using Bam.Test;

namespace Bam.Ssh.Tests.Unit;

/// <summary>
/// Unit tests for the RFC 4254 §7 forwarding wire codecs that need no channel: <c>direct-tcpip</c> and
/// <c>forwarded-tcpip</c> channel records, the <c>tcpip-forward</c> request and its bound-port reply, and
/// rejection of malformed bytes.
/// </summary>
[UnitTestMenu("ForwardingCodecShould", Selector = "fwd-codec")]
public class ForwardingCodecShould : UnitTestMenuContainer
{
    [UnitTest]
    public void RoundTripForwardingRecords()
    {
        When.A<object>("round-trips direct-tcpip, forwarded-tcpip, and tcpip-forward records through encode and parse", new object(), (ignored) =>
        {
            DirectTcpIpChannelRequest direct = DirectTcpIpChannelRequest.Parse(
                new DirectTcpIpChannelRequest("db.internal", 5432, "10.0.0.9", 51000).ToTypeSpecificData().Span);
            ForwardedTcpIpChannelInfo forwarded = ForwardedTcpIpChannelInfo.Parse(
                new ForwardedTcpIpChannelInfo("0.0.0.0", 8080, "198.51.100.7", 40000).ToTypeSpecificData().Span);
            TcpIpForwardRequest forward = TcpIpForwardRequest.Parse(
                new TcpIpForwardRequest("0.0.0.0", 0).ToRequestData().Span);
            int boundPort = TcpIpForwardRequest.ParseBoundPortReply(TcpIpForwardRequest.BuildBoundPortReply(54321).Span);

            bool malformedRejected = false;
            try
            {
                DirectTcpIpChannelRequest.Parse(new byte[] { 0, 0, 0, 5, 1, 2 });
            }
            catch (SshForwardingException)
            {
                malformedRejected = true;
            }

            return new ForwardingCodecOutcome(direct, forwarded, forward, boundPort, malformedRejected);
        })
        .TheTest
        .ShouldPass(because =>
        {
            ForwardingCodecOutcome outcome = (ForwardingCodecOutcome)because.Result;
            because.ItsTrue("a direct-tcpip record round-trips host, port, and originator", outcome.Direct.Host == "db.internal" && outcome.Direct.Port == 5432 && outcome.Direct.OriginatorAddress == "10.0.0.9" && outcome.Direct.OriginatorPort == 51000);
            because.ItsTrue("a forwarded-tcpip record round-trips connected address, port, and originator", outcome.Forwarded.ConnectedAddress == "0.0.0.0" && outcome.Forwarded.ConnectedPort == 8080 && outcome.Forwarded.OriginatorAddress == "198.51.100.7" && outcome.Forwarded.OriginatorPort == 40000);
            because.ItsTrue("a tcpip-forward request round-trips the bind address and port", outcome.Forward.BindAddress == "0.0.0.0" && outcome.Forward.BindPort == 0);
            because.ItsTrue("a bound-port reply round-trips the chosen port", outcome.BoundPort == 54321);
            because.ItsTrue("a truncated direct-tcpip record is rejected", outcome.MalformedRejected);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    private sealed class ForwardingCodecOutcome
    {
        public ForwardingCodecOutcome(DirectTcpIpChannelRequest direct, ForwardedTcpIpChannelInfo forwarded, TcpIpForwardRequest forward, int boundPort, bool malformedRejected)
        {
            Direct = direct;
            Forwarded = forwarded;
            Forward = forward;
            BoundPort = boundPort;
            MalformedRejected = malformedRejected;
        }

        public DirectTcpIpChannelRequest Direct { get; }

        public ForwardedTcpIpChannelInfo Forwarded { get; }

        public TcpIpForwardRequest Forward { get; }

        public int BoundPort { get; }

        public bool MalformedRejected { get; }
    }
}
