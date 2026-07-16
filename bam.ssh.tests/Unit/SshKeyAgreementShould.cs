using Bam.Ssh.Transport;
using Bam.Test;

namespace Bam.Ssh.Tests.Unit;

[UnitTestMenu("SshKeyAgreementShould", Selector = "kag")]
public class SshKeyAgreementShould : UnitTestMenuContainer
{
    [UnitTest]
    public void Curve25519BothSidesAgree()
    {
        RunAgreementTest(() => new Curve25519KeyExchange(), () => new Curve25519KeyExchange(), "curve25519");
    }

    [UnitTest]
    public void EcdhNistP256BothSidesAgree()
    {
        RunAgreementTest(() => new EcdhNistP256KeyExchange(), () => new EcdhNistP256KeyExchange(), "ecdh-nistp256");
    }

    [UnitTest]
    public void DhGroup14BothSidesAgree()
    {
        RunAgreementTest(() => new DiffieHellmanGroup14KeyExchange(), () => new DiffieHellmanGroup14KeyExchange(), "dh-group14");
    }

    [UnitTest]
    public void DifferentPeersProduceDifferentSecrets()
    {
        When.A<object>("two independent curve25519 exchanges yield different secrets",
            new object(),
            (ignored) =>
            {
                Curve25519KeyExchange a = new Curve25519KeyExchange();
                Curve25519KeyExchange b = new Curve25519KeyExchange();
                Curve25519KeyExchange c = new Curve25519KeyExchange();
                byte[] qa = a.CreateClientPublicValue();
                byte[] qb = b.CreateClientPublicValue();
                byte[] qc = c.CreateClientPublicValue();
                byte[] kab = a.DeriveSharedSecret(qb);
                byte[] kba = b.DeriveSharedSecret(qa);
                byte[] kac = a.DeriveSharedSecret(qc);
                return new bool[] { kab.AsSpan().SequenceEqual(kba), !kab.AsSpan().SequenceEqual(kac) };
            })
        .TheTest
        .ShouldPass(because =>
        {
            bool[] results = (bool[])because.Result;
            because.ItsTrue("the matched pair agrees", results[0]);
            because.ItsTrue("an unrelated exchange differs", results[1]);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    private void RunAgreementTest(Func<ISshKeyExchangeAlgorithm> makeA, Func<ISshKeyExchangeAlgorithm> makeB, string label)
    {
        When.A<object>($"{label} client and server derive the same shared secret",
            new object(),
            (ignored) =>
            {
                ISshKeyExchangeAlgorithm a = makeA();
                ISshKeyExchangeAlgorithm b = makeB();
                byte[] publicA = a.CreateClientPublicValue();
                byte[] publicB = b.CreateClientPublicValue();
                byte[] secretA = a.DeriveSharedSecret(publicB);
                byte[] secretB = b.DeriveSharedSecret(publicA);
                bool agree = secretA.AsSpan().SequenceEqual(secretB);
                bool nonEmpty = secretA.Length > 0;
                return new bool[] { agree, nonEmpty };
            })
        .TheTest
        .ShouldPass(because =>
        {
            bool[] results = (bool[])because.Result;
            because.ItsTrue($"{label} both sides agree", results[0]);
            because.ItsTrue($"{label} secret is non-empty", results[1]);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }
}
