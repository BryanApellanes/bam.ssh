using Bam.Ssh.Transport;
using Bam.Test;

namespace Bam.Ssh.Tests.Unit;

[UnitTestMenu("SshKexInitAndNegotiationShould", Selector = "kxi")]
public class SshKexInitAndNegotiationShould : UnitTestMenuContainer
{
    [UnitTest]
    public void RoundTripKexInitPayload()
    {
        When.A<object>("serializes and parses a KEXINIT back to equal name-lists",
            new object(),
            (ignored) =>
            {
                SshKexInit original = SshKexInit.CreateLocal(SshAlgorithmCatalog.Default, new FakeSshRandom(0x11));
                PooledBufferWriter buffer = new PooledBufferWriter(256);
                byte[] payload;
                try
                {
                    original.WritePayload(buffer);
                    payload = buffer.WrittenSpan.ToArray();
                }
                finally
                {
                    buffer.Dispose();
                }

                SshKexInit parsed = SshKexInit.Parse(payload);
                bool[] results = new bool[5];
                results[0] = payload[0] == (byte)SshMessageNumber.KexInit;
                results[1] = parsed.Cookie.Length == 16;
                results[2] = parsed.KeyExchangeAlgorithms == original.KeyExchangeAlgorithms;
                results[3] = parsed.ServerHostKeyAlgorithms == original.ServerHostKeyAlgorithms;
                results[4] = parsed.EncryptionClientToServer == original.EncryptionClientToServer
                    && !parsed.FirstKexPacketFollows;
                return results;
            })
        .TheTest
        .ShouldPass(because =>
        {
            bool[] results = (bool[])because.Result;
            because.ItsTrue("payload leads with SSH_MSG_KEXINIT", results[0]);
            because.ItsTrue("cookie is 16 bytes", results[1]);
            because.ItsTrue("kex algorithms round-trip", results[2]);
            because.ItsTrue("host key algorithms round-trip", results[3]);
            because.ItsTrue("encryption list round-trips and guess flag is false", results[4]);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void NegotiateByClientPreference()
    {
        When.A<object>("chooses the client's most-preferred common algorithm in each category",
            new object(),
            (ignored) =>
            {
                SshKexInit client = new SshKexInit(
                    new byte[16],
                    new SshNameList("curve25519-sha256", "ecdh-sha2-nistp256"),
                    new SshNameList("ssh-ed25519", "rsa-sha2-256"),
                    new SshNameList("chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"),
                    new SshNameList("chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"),
                    new SshNameList("hmac-sha2-256"),
                    new SshNameList("hmac-sha2-256"),
                    new SshNameList("none"),
                    new SshNameList("none"));
                SshKexInit server = new SshKexInit(
                    new byte[16],
                    new SshNameList("ecdh-sha2-nistp256", "curve25519-sha256"),
                    new SshNameList("rsa-sha2-256", "ssh-ed25519"),
                    new SshNameList("aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com"),
                    new SshNameList("aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com"),
                    new SshNameList("hmac-sha2-256"),
                    new SshNameList("hmac-sha2-256"),
                    new SshNameList("none"),
                    new SshNameList("none"));

                SshNegotiatedAlgorithms result = SshAlgorithmNegotiation.Negotiate(client, server);
                bool[] results = new bool[3];
                results[0] = result.KeyExchange == "curve25519-sha256";
                results[1] = result.ServerHostKey == "ssh-ed25519";
                results[2] = result.EncryptionClientToServer == "chacha20-poly1305@openssh.com";
                return results;
            })
        .TheTest
        .ShouldPass(because =>
        {
            bool[] results = (bool[])because.Result;
            because.ItsTrue("kex uses the client's first common preference", results[0]);
            because.ItsTrue("host key uses the client's first common preference", results[1]);
            because.ItsTrue("cipher uses the client's first common preference", results[2]);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void ThrowWhenNoCommonAlgorithm()
    {
        When.A<object>("throws SshKeyExchangeException when a category has no overlap",
            new object(),
            (ignored) =>
            {
                SshKexInit client = new SshKexInit(new byte[16],
                    new SshNameList("curve25519-sha256"), new SshNameList("ssh-ed25519"),
                    new SshNameList("aes256-ctr"), new SshNameList("aes256-ctr"),
                    new SshNameList("hmac-sha2-256"), new SshNameList("hmac-sha2-256"),
                    new SshNameList("none"), new SshNameList("none"));
                SshKexInit server = new SshKexInit(new byte[16],
                    new SshNameList("diffie-hellman-group14-sha256"), new SshNameList("ssh-ed25519"),
                    new SshNameList("aes256-ctr"), new SshNameList("aes256-ctr"),
                    new SshNameList("hmac-sha2-256"), new SshNameList("hmac-sha2-256"),
                    new SshNameList("none"), new SshNameList("none"));
                try
                {
                    SshAlgorithmNegotiation.Negotiate(client, server);
                    return false;
                }
                catch (SshKeyExchangeException)
                {
                    return true;
                }
            })
        .TheTest
        .ShouldPass(because =>
        {
            because.ItsTrue("no common kex algorithm throws", (bool)because.Result);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }
}
