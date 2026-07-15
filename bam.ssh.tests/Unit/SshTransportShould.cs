using Bam.Ssh.Transport;
using Bam.Test;

namespace Bam.Ssh.Tests.Unit;

[UnitTestMenu("SshTransportShould", Selector = "str")]
public class SshTransportShould : UnitTestMenuContainer
{
    [UnitTest]
    public void ConnectAndExchangePackets()
    {
        When.A<object>("connects both ends and exchanges an application packet",
            new object(),
            (ignored) =>
            {
                (SshTransport client, SshTransport server) = CreateConnectedPair();
                try
                {
                    byte[] payload = new byte[] { (byte)SshMessageNumber.KexInit, 1, 2, 3, 4 };
                    client.SendPacketAsync(payload).AsTask().GetAwaiter().GetResult();
                    using SshIncomingPacket received = server.ReceivePacketAsync().AsTask().GetAwaiter().GetResult();
                    return received.Payload.SequenceEqual(payload);
                }
                finally
                {
                    client.DisposeAsync().AsTask().GetAwaiter().GetResult();
                    server.DisposeAsync().AsTask().GetAwaiter().GetResult();
                }
            })
        .TheTest
        .ShouldPass(because =>
        {
            because.ItsTrue("the packet sent by the client arrived at the server intact", (bool)because.Result);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void SkipIgnoreAndLogDebugMessages()
    {
        When.A<object>("consumes IGNORE and DEBUG transparently and returns the real packet",
            new object(),
            (ignored) =>
            {
                CapturingSshLogger serverLogger = new CapturingSshLogger();
                (SshTransport client, SshTransport server) = CreateConnectedPair(serverLogger: serverLogger);
                try
                {
                    byte[] ignore = new byte[] { (byte)SshMessageNumber.Ignore, 0, 0, 0, 0 };
                    byte[] debug = BuildDebug("hello from peer");
                    byte[] real = new byte[] { (byte)SshMessageNumber.ServiceRequest, 42 };

                    client.SendPacketAsync(ignore).AsTask().GetAwaiter().GetResult();
                    client.SendPacketAsync(debug).AsTask().GetAwaiter().GetResult();
                    client.SendPacketAsync(real).AsTask().GetAwaiter().GetResult();

                    using SshIncomingPacket received = server.ReceivePacketAsync().AsTask().GetAwaiter().GetResult();
                    bool gotReal = received.MessageNumber == (byte)SshMessageNumber.ServiceRequest;
                    bool loggedDebug = serverLogger.Messages.Exists(m => m.Contains("hello from peer"));
                    return new bool[] { gotReal, loggedDebug };
                }
                finally
                {
                    client.DisposeAsync().AsTask().GetAwaiter().GetResult();
                    server.DisposeAsync().AsTask().GetAwaiter().GetResult();
                }
            })
        .TheTest
        .ShouldPass(because =>
        {
            bool[] results = (bool[])because.Result;
            because.ItsTrue("the ServiceRequest packet was returned, past IGNORE and DEBUG", results[0]);
            because.ItsTrue("the DEBUG message content was logged", results[1]);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void ThrowOnReceivingDisconnect()
    {
        When.A<object>("raises SshDisconnectException when the peer sends DISCONNECT",
            new object(),
            (ignored) =>
            {
                (SshTransport client, SshTransport server) = CreateConnectedPair();
                try
                {
                    client.SendDisconnectAsync(SshDisconnectReason.ByApplication, "goodbye").AsTask().GetAwaiter().GetResult();
                    try
                    {
                        using SshIncomingPacket _ = server.ReceivePacketAsync().AsTask().GetAwaiter().GetResult();
                        return false;
                    }
                    catch (SshDisconnectException disconnect)
                    {
                        return disconnect.Reason == SshDisconnectReason.ByApplication && disconnect.Description == "goodbye";
                    }
                }
                finally
                {
                    client.DisposeAsync().AsTask().GetAwaiter().GetResult();
                    server.DisposeAsync().AsTask().GetAwaiter().GetResult();
                }
            })
        .TheTest
        .ShouldPass(because =>
        {
            because.ItsTrue("the disconnect reason and description surfaced", (bool)because.Result);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void SwapCiphersOnApplyKeys()
    {
        When.A<object>("routes packets through the swapped cipher after ApplyKeys",
            new object(),
            (ignored) =>
            {
                (SshTransport client, SshTransport server) = CreateConnectedPair();
                try
                {
                    RecordingPacketCipher clientOut = new RecordingPacketCipher(NonePacketCipher.Instance);
                    RecordingPacketCipher serverIn = new RecordingPacketCipher(NonePacketCipher.Instance);
                    client.ApplyKeys(NonePacketCipher.Instance, clientOut);
                    server.ApplyKeys(serverIn, NonePacketCipher.Instance);

                    byte[] payload = new byte[] { (byte)SshMessageNumber.NewKeys, 7, 7, 7 };
                    client.SendPacketAsync(payload).AsTask().GetAwaiter().GetResult();
                    using SshIncomingPacket received = server.ReceivePacketAsync().AsTask().GetAwaiter().GetResult();

                    bool intact = received.Payload.SequenceEqual(payload);
                    return new int[] { clientOut.OutgoingCount, serverIn.IncomingCount, intact ? 1 : 0 };
                }
                finally
                {
                    client.DisposeAsync().AsTask().GetAwaiter().GetResult();
                    server.DisposeAsync().AsTask().GetAwaiter().GetResult();
                }
            })
        .TheTest
        .ShouldPass(because =>
        {
            int[] results = (int[])because.Result;
            because.ItsTrue("the swapped outbound cipher transformed the packet", results[0] == 1);
            because.ItsTrue("the swapped inbound cipher processed the packet", results[1] == 1);
            because.ItsTrue("the payload survived the swapped ciphers intact", results[2] == 1);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    private static (SshTransport Client, SshTransport Server) CreateConnectedPair(
        ISshLogger? clientLogger = null, ISshLogger? serverLogger = null)
    {
        (LoopbackDuplexStream clientStream, LoopbackDuplexStream serverStream) = LoopbackDuplexStream.CreatePair();
        SshTransport client = new SshTransport(clientStream, new SshTransportOptions("Bam.Ssh_Client"), clientLogger);
        SshTransport server = new SshTransport(serverStream, new SshTransportOptions("Bam.Ssh_Server"), serverLogger);
        Task clientConnect = client.ConnectAsync().AsTask();
        Task serverConnect = server.ConnectAsync().AsTask();
        Task.WhenAll(clientConnect, serverConnect).GetAwaiter().GetResult();
        return (client, server);
    }

    private static byte[] BuildDebug(string message)
    {
        using PooledBufferWriter writer = new PooledBufferWriter(16 + message.Length);
        SshWireWriter wire = new SshWireWriter(writer);
        wire.WriteByte((byte)SshMessageNumber.Debug);
        wire.WriteBoolean(true);
        wire.WriteText(message);
        wire.WriteText(string.Empty);
        return writer.WrittenSpan.ToArray();
    }
}
