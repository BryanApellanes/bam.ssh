using System.Security.Cryptography;
using Bam.Ssh.Transport;
using Bam.Test;

namespace Bam.Ssh.Tests.Unit;

[UnitTestMenu("SshHostKeyShould", Selector = "hk")]
public class SshHostKeyShould : UnitTestMenuContainer
{
    [UnitTest]
    public void VerifyEd25519SignatureAndRejectTampering()
    {
        RunHostKeyTest(TestHostKeys.CreateEd25519(), SshAlgorithmNames.SshEd25519, "ed25519");
    }

    [UnitTest]
    public void VerifyEcdsaNistP256Signature()
    {
        RunHostKeyTest(TestHostKeys.CreateEcdsaNistP256(), SshAlgorithmNames.EcdsaSha2Nistp256, "ecdsa-nistp256");
    }

    [UnitTest]
    public void VerifyRsaSha2256Signature()
    {
        RunHostKeyTest(TestHostKeys.CreateRsa(SshAlgorithmNames.RsaSha2256), SshAlgorithmNames.SshRsaKeyType, "rsa-sha2-256");
    }

    [UnitTest]
    public void VerifyRsaSha2512Signature()
    {
        RunHostKeyTest(TestHostKeys.CreateRsa(SshAlgorithmNames.RsaSha2512), SshAlgorithmNames.SshRsaKeyType, "rsa-sha2-512");
    }

    [UnitTest]
    public void ProduceOpenSshStyleFingerprint()
    {
        When.A<object>("formats the fingerprint as SHA256:base64 without padding",
            new object(),
            (ignored) =>
            {
                (byte[] keyBlob, Func<byte[], byte[]> _) = TestHostKeys.CreateEd25519();
                ISshHostKey hostKey = SshHostKeyParser.Parse(keyBlob);
                string fingerprint = hostKey.Fingerprint;
                return new bool[] { fingerprint.StartsWith("SHA256:", StringComparison.Ordinal), !fingerprint.EndsWith("=", StringComparison.Ordinal) };
            })
        .TheTest
        .ShouldPass(because =>
        {
            bool[] results = (bool[])because.Result;
            because.ItsTrue("fingerprint has the SHA256: prefix", results[0]);
            because.ItsTrue("fingerprint base64 is unpadded", results[1]);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    private void RunHostKeyTest((byte[] KeyBlob, Func<byte[], byte[]> Sign) key, string expectedAlgorithm, string label)
    {
        When.A<object>($"{label}: parses the blob, verifies a real signature, and rejects a tampered one",
            new object(),
            (ignored) =>
            {
                byte[] hash = SHA256.HashData(System.Text.Encoding.ASCII.GetBytes($"exchange hash for {label}"));
                byte[] signatureBlob = key.Sign(hash);

                ISshHostKey hostKey = SshHostKeyParser.Parse(key.KeyBlob);
                bool algorithmMatches = hostKey.Algorithm == expectedAlgorithm;
                bool verifies = hostKey.Verify(hash, signatureBlob);

                byte[] tamperedHash = (byte[])hash.Clone();
                tamperedHash[0] ^= 0x01;
                bool rejectsTamperedHash = !hostKey.Verify(tamperedHash, signatureBlob);

                byte[] tamperedSignature = (byte[])signatureBlob.Clone();
                tamperedSignature[tamperedSignature.Length - 1] ^= 0x01;
                bool rejectsTamperedSignature = !hostKey.Verify(hash, tamperedSignature);

                return new bool[] { algorithmMatches, verifies, rejectsTamperedHash, rejectsTamperedSignature };
            })
        .TheTest
        .ShouldPass(because =>
        {
            bool[] results = (bool[])because.Result;
            because.ItsTrue($"{label} algorithm name is correct", results[0]);
            because.ItsTrue($"{label} a valid signature verifies", results[1]);
            because.ItsTrue($"{label} a tampered hash is rejected", results[2]);
            because.ItsTrue($"{label} a tampered signature is rejected", results[3]);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }
}
