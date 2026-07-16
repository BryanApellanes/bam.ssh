using System.Security.Cryptography;
using System.Text;
using Bam.Ssh.Client;
using Bam.Ssh.Transport;
using Bam.Test;

namespace Bam.Ssh.Tests.Unit;

/// <summary>
/// Verifies the OpenSSH known_hosts trust logic in isolation: trust-on-first-use accepts and records a
/// first-seen key; an already-present matching key is accepted; a changed key of the same type is rejected
/// as a possible MITM; strict mode rejects an unknown key; and an HMAC-SHA1 hashed host entry matches.
/// </summary>
[UnitTestMenu("SshKnownHostsVerifierShould", Selector = "knownhosts")]
public class SshKnownHostsVerifierShould : UnitTestMenuContainer
{
    [UnitTest]
    public void AcceptAndRecordAFirstSeenKeyUnderTofu()
    {
        When.A<object>("accepts and records a first-seen key under TOFU", new object(), (ignored) =>
        {
            string path = TempFile();
            try
            {
                ISshHostKey key = MakeHostKey();
                KnownHostsHostKeyVerifier verifier = KnownHostsHostKeyVerifier.Tofu(path);
                bool accepted = Verify(verifier, "example.com", 22, key);
                bool recorded = File.Exists(path) && File.ReadAllText(path).Contains(Convert.ToBase64String(key.KeyBlob.Span));
                // A second connection with the same key must still be accepted (now it is known).
                bool acceptedAgain = Verify(KnownHostsHostKeyVerifier.Tofu(path), "example.com", 22, key);
                return accepted && recorded && acceptedAgain;
            }
            finally
            {
                Delete(path);
            }
        })
        .TheTest
        .ShouldPass(because => because.ItsTrue("the first-seen key was accepted, recorded, and re-accepted", (bool)because.Result))
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RejectAChangedKey()
    {
        When.A<object>("rejects a key that differs from the stored one", new object(), (ignored) =>
        {
            string path = TempFile();
            try
            {
                ISshHostKey stored = MakeHostKey(0x42);
                ISshHostKey different = MakeHostKey(0x99);
                File.WriteAllText(path, $"example.com {stored.Algorithm} {Convert.ToBase64String(stored.KeyBlob.Span)}\n");
                bool rejected = !Verify(KnownHostsHostKeyVerifier.Tofu(path), "example.com", 22, different);
                bool storedStillAccepted = Verify(KnownHostsHostKeyVerifier.Tofu(path), "example.com", 22, stored);
                return rejected && storedStillAccepted;
            }
            finally
            {
                Delete(path);
            }
        })
        .TheTest
        .ShouldPass(because => because.ItsTrue("a changed key is rejected while the stored key is accepted", (bool)because.Result))
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RejectAnUnknownKeyUnderStrictMode()
    {
        When.A<object>("rejects an unknown key under strict mode", new object(), (ignored) =>
        {
            string path = TempFile();
            try
            {
                File.WriteAllText(path, "# empty known_hosts\n");
                ISshHostKey key = MakeHostKey();
                bool rejected = !Verify(KnownHostsHostKeyVerifier.Strict(path), "example.com", 22, key);
                bool notRecorded = !File.ReadAllText(path).Contains(Convert.ToBase64String(key.KeyBlob.Span));
                return rejected && notRecorded;
            }
            finally
            {
                Delete(path);
            }
        })
        .TheTest
        .ShouldPass(because => because.ItsTrue("strict mode rejected the unknown key and recorded nothing", (bool)because.Result))
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void MatchAHashedHostEntry()
    {
        When.A<object>("matches an HMAC-SHA1 hashed host entry", new object(), (ignored) =>
        {
            string path = TempFile();
            try
            {
                ISshHostKey key = MakeHostKey();
                byte[] salt = new byte[20];
                for (int i = 0; i < salt.Length; i++)
                {
                    salt[i] = (byte)(i + 1);
                }
                byte[] hash = HMACSHA1.HashData(salt, Encoding.ASCII.GetBytes("secret-host"));
                string hashedHost = $"|1|{Convert.ToBase64String(salt)}|{Convert.ToBase64String(hash)}";
                File.WriteAllText(path, $"{hashedHost} {key.Algorithm} {Convert.ToBase64String(key.KeyBlob.Span)}\n");

                bool matched = Verify(KnownHostsHostKeyVerifier.Strict(path), "secret-host", 22, key);
                bool otherHostRejected = !Verify(KnownHostsHostKeyVerifier.Strict(path), "other-host", 22, key);
                return matched && otherHostRejected;
            }
            finally
            {
                Delete(path);
            }
        })
        .TheTest
        .ShouldPass(because => because.ItsTrue("the hashed entry matched its host and only its host", (bool)because.Result))
        .SoBeHappy()
        .UnlessItFailed();
    }

    private static bool Verify(ISshHostKeyVerifier verifier, string host, int port, ISshHostKey key)
    {
        SshHostKeyVerificationContext context = new SshHostKeyVerificationContext(host, port, key);
        return verifier.VerifyAsync(context).AsTask().GetAwaiter().GetResult();
    }

    private static ISshHostKey MakeHostKey(byte seed = 0x42)
    {
        (byte[] hostKeyBlob, Func<byte[], byte[]> sign) = TestHostKeys.CreateEd25519(seed);
        _ = sign;
        return SshHostKeyParser.Parse(hostKeyBlob);
    }

    private static string TempFile()
    {
        return Path.Combine(Path.GetTempPath(), "bam-ssh-knownhosts-" + Guid.NewGuid().ToString("N") + ".txt");
    }

    private static void Delete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (IOException)
        {
        }
    }
}
