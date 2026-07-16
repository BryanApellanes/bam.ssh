using System.Security.Cryptography;
using Bam.Ssh.Transport;
using Bam.Test;

namespace Bam.Ssh.Tests.Unit;

[UnitTestMenu("SshExchangeHashAndDerivationShould", Selector = "xhd")]
public class SshExchangeHashAndDerivationShould : UnitTestMenuContainer
{
    [UnitTest]
    public void ComputeExchangeHashDeterministicallyAndSensitively()
    {
        When.A<object>("produces the same H for identical inputs and a different H when any input changes",
            new object(),
            (ignored) =>
            {
                byte[] vC = new byte[] { 1, 2, 3 };
                byte[] vS = new byte[] { 4, 5, 6 };
                byte[] iC = new byte[] { 20, 7 };
                byte[] iS = new byte[] { 20, 8 };
                byte[] kS = new byte[] { 9, 9, 9 };
                // High bit set: as an mpint these gain a 0x00 sign byte, so the string and mpint
                // encodings differ in length — which must change H (h1 vs h4).
                byte[] qC = new byte[] { 0x80, 0x11 };
                byte[] qS = new byte[] { 0x80, 0x22 };
                byte[] k = new byte[] { 0x7F, 0x00 };

                byte[] h1 = SshExchangeHash.Compute(HashAlgorithmName.SHA256, vC, vS, iC, iS, kS, qC, qS, SshKeyExchangePublicValueFormat.String, k);
                byte[] h2 = SshExchangeHash.Compute(HashAlgorithmName.SHA256, vC, vS, iC, iS, kS, qC, qS, SshKeyExchangePublicValueFormat.String, k);
                byte[] h3 = SshExchangeHash.Compute(HashAlgorithmName.SHA256, vC, vS, iC, iS, kS, qC, qS, SshKeyExchangePublicValueFormat.String, new byte[] { 0x7F, 0x01 });
                byte[] h4 = SshExchangeHash.Compute(HashAlgorithmName.SHA256, vC, vS, iC, iS, kS, qC, qS, SshKeyExchangePublicValueFormat.MultiPrecisionInteger, k);

                bool[] results = new bool[4];
                results[0] = h1.AsSpan().SequenceEqual(h2);
                results[1] = h1.Length == 32;
                results[2] = !h1.AsSpan().SequenceEqual(h3);
                results[3] = !h1.AsSpan().SequenceEqual(h4);
                return results;
            })
        .TheTest
        .ShouldPass(because =>
        {
            bool[] results = (bool[])because.Result;
            because.ItsTrue("identical inputs give identical H", results[0]);
            because.ItsTrue("SHA-256 H is 32 bytes", results[1]);
            because.ItsTrue("changing the shared secret changes H", results[2]);
            because.ItsTrue("changing the public-value encoding changes H", results[3]);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void DeriveKeysWithExtensionAndPrefixConsistency()
    {
        When.A<object>("extends past one digest and keeps the prefix relationship",
            new object(),
            (ignored) =>
            {
                byte[] k = new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89 };
                byte[] h = SHA256.HashData(new byte[] { 1 });
                byte[] sessionId = h;

                byte[] key32 = SshKeyDerivation.DeriveKey(HashAlgorithmName.SHA256, k, h, (byte)'C', sessionId, 32);
                byte[] key64 = SshKeyDerivation.DeriveKey(HashAlgorithmName.SHA256, k, h, (byte)'C', sessionId, 64);
                byte[] key64Again = SshKeyDerivation.DeriveKey(HashAlgorithmName.SHA256, k, h, (byte)'C', sessionId, 64);
                byte[] keyOtherLetter = SshKeyDerivation.DeriveKey(HashAlgorithmName.SHA256, k, h, (byte)'D', sessionId, 32);

                bool[] results = new bool[5];
                results[0] = key32.Length == 32 && key64.Length == 64;
                results[1] = key64.AsSpan(0, 32).SequenceEqual(key32);        // prefix relationship
                results[2] = key64.AsSpan().SequenceEqual(key64Again);         // deterministic
                results[3] = !key32.AsSpan().SequenceEqual(keyOtherLetter);    // letter matters
                results[4] = !key64.AsSpan(0, 32).SequenceEqual(key64.AsSpan(32, 32)); // two distinct blocks
                return results;
            })
        .TheTest
        .ShouldPass(because =>
        {
            bool[] results = (bool[])because.Result;
            because.ItsTrue("requested lengths are honored", results[0]);
            because.ItsTrue("a longer key extends the shorter one (RFC 7.2 prefix)", results[1]);
            because.ItsTrue("derivation is deterministic", results[2]);
            because.ItsTrue("the distinguishing letter changes the key", results[3]);
            because.ItsTrue("the extension block differs from the first block", results[4]);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }
}
