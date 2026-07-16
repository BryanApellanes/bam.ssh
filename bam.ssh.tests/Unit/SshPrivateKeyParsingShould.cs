using Bam.Ssh.Authentication;
using Bam.Ssh.Transport;
using Bam.Test;

namespace Bam.Ssh.Tests.Unit;

/// <summary>
/// Proves the private-key reader loads each key type from both the OpenSSH v1 and PKCS#8/PEM
/// containers and that every parsed key produces a signature the production transport host-key
/// verifier accepts — closing the loop between client signing and server verification. Also proves the
/// documented rejection of encrypted OpenSSH v1 keys.
/// </summary>
[UnitTestMenu("SshPrivateKeyParsingShould", Selector = "pk")]
public class SshPrivateKeyParsingShould : UnitTestMenuContainer
{
    [UnitTest]
    public void ParseOpenSshKeysAndProduceVerifiableSignatures()
    {
        When.A<object>("parses OpenSSH v1 ed25519/ecdsa/rsa keys and verifies their signatures",
            new object(),
            (ignored) =>
            {
                bool ed25519 = SignsAndVerifies(SshPrivateKeyReader.Read(PrivateKeyTestSupport.OpenSshEd25519()));
                bool ecdsa = SignsAndVerifies(SshPrivateKeyReader.Read(PrivateKeyTestSupport.OpenSshEcdsa()));
                bool rsa = SignsAndVerifies(SshPrivateKeyReader.Read(PrivateKeyTestSupport.OpenSshRsa()));
                return new bool[] { ed25519, ecdsa, rsa };
            })
        .TheTest
        .ShouldPass(because =>
        {
            bool[] results = (bool[])because.Result;
            because.ItsTrue("the OpenSSH ed25519 key signs verifiably", results[0]);
            because.ItsTrue("the OpenSSH ecdsa-sha2-nistp256 key signs verifiably", results[1]);
            because.ItsTrue("the OpenSSH ssh-rsa key signs verifiably", results[2]);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void ParsePkcs8PemKeysAndProduceVerifiableSignatures()
    {
        When.A<object>("parses PKCS#8/PEM ed25519/ecdsa/rsa keys and verifies their signatures",
            new object(),
            (ignored) =>
            {
                bool ed25519 = SignsAndVerifies(SshPrivateKeyReader.Read(PrivateKeyTestSupport.Pkcs8Ed25519()));
                bool ecdsa = SignsAndVerifies(SshPrivateKeyReader.Read(PrivateKeyTestSupport.Pkcs8Ecdsa()));
                bool rsa = SignsAndVerifies(SshPrivateKeyReader.Read(PrivateKeyTestSupport.Pkcs8Rsa()));
                return new bool[] { ed25519, ecdsa, rsa };
            })
        .TheTest
        .ShouldPass(because =>
        {
            bool[] results = (bool[])because.Result;
            because.ItsTrue("the PKCS#8 ed25519 key signs verifiably", results[0]);
            because.ItsTrue("the PKCS#8 ecdsa-sha2-nistp256 key signs verifiably", results[1]);
            because.ItsTrue("the PKCS#8 rsa key signs verifiably", results[2]);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RejectEncryptedOpenSshKeys()
    {
        When.A<object>("rejects an encrypted OpenSSH v1 key with a clear exception",
            new object(),
            (ignored) =>
            {
                bool threw = false;
                try
                {
                    SshPrivateKeyReader.Read(PrivateKeyTestSupport.EncryptedOpenSshEd25519());
                }
                catch (SshAuthenticationException)
                {
                    threw = true;
                }
                return threw;
            })
        .TheTest
        .ShouldPass(because => because.ItsTrue("an encrypted OpenSSH key raises SshAuthenticationException", (bool)because.Result))
        .SoBeHappy()
        .UnlessItFailed();
    }

    private static bool SignsAndVerifies(ISshPrivateKey key)
    {
        byte[] message = System.Text.Encoding.ASCII.GetBytes("bam.ssh phase 5 authentication signing round-trip payload");
        byte[] signature = key.Sign(message);
        ISshHostKey verifier = SshHostKeyParser.Parse(key.PublicKeyBlob.Span);
        return verifier.Verify(message, signature);
    }
}
