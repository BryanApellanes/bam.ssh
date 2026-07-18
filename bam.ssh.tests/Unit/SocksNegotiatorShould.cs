using System.Text;
using Bam.Ssh.Forwarding;
using Bam.Test;

namespace Bam.Ssh.Tests.Unit;

/// <summary>
/// Unit tests for <see cref="SocksNegotiator"/>: a SOCKS5 no-authentication CONNECT and a SOCKS4a CONNECT are
/// parsed to the right destination and produce the correct version-specific replies, and an unknown SOCKS
/// version is rejected.
/// </summary>
[UnitTestMenu("SocksNegotiatorShould", Selector = "socks")]
public class SocksNegotiatorShould : UnitTestMenuContainer
{
    [UnitTest]
    public void NegotiateSocks5AndSocks4a()
    {
        When.A<object>("parses SOCKS5 and SOCKS4a CONNECT requests and writes the right replies", new object(), (ignored) =>
        {
            // SOCKS5: greeting (ver 5, 1 method, no-auth) + CONNECT to 127.0.0.1:8080 (IPv4).
            byte[] socks5Input = new byte[]
            {
                0x05, 0x01, 0x00,
                0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x1F, 0x90,
            };
            MemoryStream socks5Output = new MemoryStream();
            SocksNegotiator socks5 = new SocksNegotiator();
            PairStream socks5Pair = new PairStream(socks5Input, socks5Output);
            SocksTarget socks5Target = socks5.NegotiateAsync(socks5Pair).AsTask().GetAwaiter().GetResult();
            socks5.WriteSuccessReplyAsync(socks5Pair).AsTask().GetAwaiter().GetResult();
            byte[] socks5Reply = socks5Output.ToArray();

            // SOCKS4a: ver 4, CONNECT, port 8080, ip 0.0.0.1 (marker), empty userid, "example.com".
            List<byte> socks4Bytes = new List<byte> { 0x04, 0x01, 0x1F, 0x90, 0, 0, 0, 1, 0x00 };
            socks4Bytes.AddRange(Encoding.ASCII.GetBytes("example.com"));
            socks4Bytes.Add(0x00);
            MemoryStream socks4Output = new MemoryStream();
            SocksNegotiator socks4 = new SocksNegotiator();
            PairStream socks4Pair = new PairStream(socks4Bytes.ToArray(), socks4Output);
            SocksTarget socks4Target = socks4.NegotiateAsync(socks4Pair).AsTask().GetAwaiter().GetResult();
            socks4.WriteSuccessReplyAsync(socks4Pair).AsTask().GetAwaiter().GetResult();
            byte[] socks4Reply = socks4Output.ToArray();

            bool unknownRejected = false;
            try
            {
                new SocksNegotiator().NegotiateAsync(new PairStream(new byte[] { 0x09 }, new MemoryStream())).AsTask().GetAwaiter().GetResult();
            }
            catch (SshForwardingException)
            {
                unknownRejected = true;
            }

            return new SocksOutcome(socks5Target, socks5Reply, socks4Target, socks4Reply, unknownRejected);
        })
        .TheTest
        .ShouldPass(because =>
        {
            SocksOutcome outcome = (SocksOutcome)because.Result;
            because.ItsTrue("SOCKS5 parses the IPv4 destination and port", outcome.Socks5Target.Host == "127.0.0.1" && outcome.Socks5Target.Port == 8080);
            because.ItsTrue("SOCKS5 writes the no-auth selection then a success CONNECT reply", outcome.Socks5Reply.Length == 12 && outcome.Socks5Reply[0] == 0x05 && outcome.Socks5Reply[1] == 0x00 && outcome.Socks5Reply[2] == 0x05 && outcome.Socks5Reply[3] == 0x00);
            because.ItsTrue("SOCKS4a parses the domain destination and port", outcome.Socks4Target.Host == "example.com" && outcome.Socks4Target.Port == 8080);
            because.ItsTrue("SOCKS4a writes an 8-byte granted reply", outcome.Socks4Reply.Length == 8 && outcome.Socks4Reply[0] == 0x00 && outcome.Socks4Reply[1] == 0x5A);
            because.ItsTrue("an unknown SOCKS version is rejected", outcome.UnknownRejected);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    private sealed class SocksOutcome
    {
        public SocksOutcome(SocksTarget socks5Target, byte[] socks5Reply, SocksTarget socks4Target, byte[] socks4Reply, bool unknownRejected)
        {
            Socks5Target = socks5Target;
            Socks5Reply = socks5Reply;
            Socks4Target = socks4Target;
            Socks4Reply = socks4Reply;
            UnknownRejected = unknownRejected;
        }

        public SocksTarget Socks5Target { get; }

        public byte[] Socks5Reply { get; }

        public SocksTarget Socks4Target { get; }

        public byte[] Socks4Reply { get; }

        public bool UnknownRejected { get; }
    }

    /// <summary>
    /// A minimal duplex stream that reads from a fixed input buffer and appends writes to an output buffer,
    /// so a negotiator's interleaved reads and reply writes can be driven and inspected in a unit test.
    /// </summary>
    private sealed class PairStream : Stream
    {
        private readonly MemoryStream _input;
        private readonly MemoryStream _output;

        public PairStream(byte[] input, MemoryStream output)
        {
            _input = new MemoryStream(input);
            _output = output;
        }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) => _input.Read(buffer, offset, count);

        public override void Write(byte[] buffer, int offset, int count) => _output.Write(buffer, offset, count);

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
