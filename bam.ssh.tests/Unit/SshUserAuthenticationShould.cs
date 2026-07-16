using Bam.Ssh.Authentication;
using Bam.Test;

namespace Bam.Ssh.Tests.Unit;

/// <summary>
/// End-to-end proof of the RFC 4252 client authentication dialog over a fully keyed loopback transport
/// against a test server that uses the production wire primitives and host-key verifiers: password,
/// publickey (ed25519/ecdsa/rsa), and keyboard-interactive all authenticate; rejections are reported
/// (not thrown); the method list falls through on failure; the none probe surfaces the continuable
/// methods; and banners reach the sink.
/// </summary>
[UnitTestMenu("SshUserAuthenticationShould", Selector = "auth")]
public class SshUserAuthenticationShould : UnitTestMenuContainer
{
    [UnitTest]
    public void AuthenticateWithCorrectPassword()
    {
        When.A<object>("authenticates with the correct password", new object(), (ignored) =>
        {
            TestUserAuthServer server = new TestUserAuthServer { AcceptPassword = "correct-horse" };
            SshAuthenticationResult result = AuthenticationTestSupport.RunAuthentication(
                server, "tester", new ISshAuthenticationMethod[] { new PasswordAuthenticationMethod("correct-horse") });
            return result;
        })
        .TheTest
        .ShouldPass(because =>
        {
            SshAuthenticationResult result = (SshAuthenticationResult)because.Result;
            because.ItsTrue("authentication succeeded", result.Succeeded);
            because.ItsTrue("the winning method was password", result.MethodUsed == SshAuthenticationNames.Password);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RejectWrongPasswordAndSurfaceContinuableMethods()
    {
        When.A<object>("reports a rejection with the continuable methods when the password is wrong", new object(), (ignored) =>
        {
            TestUserAuthServer server = new TestUserAuthServer { AcceptPassword = "correct-horse" };
            SshAuthenticationResult result = AuthenticationTestSupport.RunAuthentication(
                server, "tester", new ISshAuthenticationMethod[] { new PasswordAuthenticationMethod("wrong") });
            return result;
        })
        .TheTest
        .ShouldPass(because =>
        {
            SshAuthenticationResult result = (SshAuthenticationResult)because.Result;
            because.ItsFalse("authentication did not succeed", result.Succeeded);
            because.ItsTrue("the server's continuable methods were surfaced", result.MethodsThatCanContinue.Contains(SshAuthenticationNames.Password));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void AuthenticateWithPublicKeyForEveryKeyType()
    {
        When.A<object>("authenticates with ed25519, ecdsa, and rsa public keys", new object(), (ignored) =>
        {
            bool ed25519 = PublicKeySucceeds(SshPrivateKeyReader.Read(PrivateKeyTestSupport.OpenSshEd25519()));
            bool ecdsa = PublicKeySucceeds(SshPrivateKeyReader.Read(PrivateKeyTestSupport.OpenSshEcdsa()));
            bool rsa = PublicKeySucceeds(SshPrivateKeyReader.Read(PrivateKeyTestSupport.OpenSshRsa()));
            return new bool[] { ed25519, ecdsa, rsa };
        })
        .TheTest
        .ShouldPass(because =>
        {
            bool[] results = (bool[])because.Result;
            because.ItsTrue("ed25519 publickey authentication succeeds", results[0]);
            because.ItsTrue("ecdsa-sha2-nistp256 publickey authentication succeeds", results[1]);
            because.ItsTrue("rsa publickey authentication succeeds", results[2]);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RejectPublicKeyThatTheServerDoesNotAccept()
    {
        When.A<object>("reports a rejection when the offered public key is not authorized", new object(), (ignored) =>
        {
            ISshPrivateKey clientKey = SshPrivateKeyReader.Read(PrivateKeyTestSupport.OpenSshEd25519());
            // Server accepts a *different* key's blob, so the offered key is refused.
            TestUserAuthServer server = new TestUserAuthServer { AcceptPublicKeyBlob = new byte[] { 0x00, 0x01, 0x02 } };
            SshAuthenticationResult result = AuthenticationTestSupport.RunAuthentication(
                server, "tester", new ISshAuthenticationMethod[] { new PublicKeyAuthenticationMethod(clientKey) });
            return result;
        })
        .TheTest
        .ShouldPass(because => because.ItsFalse("authentication did not succeed", ((SshAuthenticationResult)because.Result).Succeeded))
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void AuthenticateWithKeyboardInteractive()
    {
        When.A<object>("answers a keyboard-interactive challenge", new object(), (ignored) =>
        {
            TestUserAuthServer server = new TestUserAuthServer
            {
                KeyboardInteractivePrompt = "Password: ",
                KeyboardInteractiveAnswer = "kbd-secret"
            };
            ISshKeyboardInteractiveResponder responder = new ScriptedKeyboardInteractiveResponder("kbd-secret");
            SshAuthenticationResult result = AuthenticationTestSupport.RunAuthentication(
                server, "tester", new ISshAuthenticationMethod[] { new KeyboardInteractiveAuthenticationMethod(responder) });
            return result;
        })
        .TheTest
        .ShouldPass(because =>
        {
            SshAuthenticationResult result = (SshAuthenticationResult)because.Result;
            because.ItsTrue("keyboard-interactive authentication succeeds", result.Succeeded);
            because.ItsTrue("the winning method was keyboard-interactive", result.MethodUsed == SshAuthenticationNames.KeyboardInteractive);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void ProbeWithNoneToDiscoverContinuableMethods()
    {
        When.A<object>("uses the none method to discover the acceptable methods", new object(), (ignored) =>
        {
            TestUserAuthServer server = new TestUserAuthServer(); // accepts nothing
            SshAuthenticationResult result = AuthenticationTestSupport.RunAuthentication(
                server, "tester", new ISshAuthenticationMethod[] { new NoneAuthenticationMethod() });
            return result;
        })
        .TheTest
        .ShouldPass(because =>
        {
            SshAuthenticationResult result = (SshAuthenticationResult)because.Result;
            because.ItsFalse("the none probe did not authenticate", result.Succeeded);
            because.ItsTrue("publickey was listed as continuable", result.MethodsThatCanContinue.Contains(SshAuthenticationNames.PublicKey));
            because.ItsTrue("password was listed as continuable", result.MethodsThatCanContinue.Contains(SshAuthenticationNames.Password));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void FallBackToTheNextMethodWhenOneFails()
    {
        When.A<object>("falls back to password after publickey is refused", new object(), (ignored) =>
        {
            ISshPrivateKey clientKey = SshPrivateKeyReader.Read(PrivateKeyTestSupport.OpenSshEd25519());
            TestUserAuthServer server = new TestUserAuthServer { AcceptPassword = "fallback-pw" }; // publickey not accepted
            SshAuthenticationResult result = AuthenticationTestSupport.RunAuthentication(
                server,
                "tester",
                new ISshAuthenticationMethod[]
                {
                    new PublicKeyAuthenticationMethod(clientKey),
                    new PasswordAuthenticationMethod("fallback-pw")
                });
            return result;
        })
        .TheTest
        .ShouldPass(because =>
        {
            SshAuthenticationResult result = (SshAuthenticationResult)because.Result;
            because.ItsTrue("authentication ultimately succeeded", result.Succeeded);
            because.ItsTrue("the winning method was password (the fallback)", result.MethodUsed == SshAuthenticationNames.Password);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void SurfaceServerBannerToTheSink()
    {
        When.A<object>("surfaces a pre-auth banner to the sink", new object(), (ignored) =>
        {
            TestUserAuthServer server = new TestUserAuthServer { AcceptPassword = "pw", Banner = "Authorized use only." };
            CapturingBannerSink sink = new CapturingBannerSink();
            SshAuthenticationResult result = AuthenticationTestSupport.RunAuthentication(
                server, "tester", new ISshAuthenticationMethod[] { new PasswordAuthenticationMethod("pw") }, sink);
            return new BannerOutcome(result.Succeeded, sink.Banners.Count == 1 && sink.Banners[0] == "Authorized use only.");
        })
        .TheTest
        .ShouldPass(because =>
        {
            BannerOutcome outcome = (BannerOutcome)because.Result;
            because.ItsTrue("authentication succeeded", outcome.Authenticated);
            because.ItsTrue("the banner reached the sink", outcome.BannerReceived);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    private static bool PublicKeySucceeds(ISshPrivateKey key)
    {
        TestUserAuthServer server = new TestUserAuthServer { AcceptPublicKeyBlob = key.PublicKeyBlob.ToArray() };
        SshAuthenticationResult result = AuthenticationTestSupport.RunAuthentication(
            server, "tester", new ISshAuthenticationMethod[] { new PublicKeyAuthenticationMethod(key) });
        return result.Succeeded && result.MethodUsed == SshAuthenticationNames.PublicKey;
    }

    private sealed class BannerOutcome
    {
        public BannerOutcome(bool authenticated, bool bannerReceived)
        {
            Authenticated = authenticated;
            BannerReceived = bannerReceived;
        }

        public bool Authenticated { get; }

        public bool BannerReceived { get; }
    }

    private sealed class ScriptedKeyboardInteractiveResponder : ISshKeyboardInteractiveResponder
    {
        private readonly string _answer;

        public ScriptedKeyboardInteractiveResponder(string answer)
        {
            _answer = answer;
        }

        public IReadOnlyList<string> Respond(string name, string instruction, IReadOnlyList<SshKeyboardInteractivePrompt> prompts)
        {
            string[] responses = new string[prompts.Count];
            for (int i = 0; i < responses.Length; i++)
            {
                responses[i] = _answer;
            }
            return responses;
        }
    }

    private sealed class CapturingBannerSink : ISshBannerSink
    {
        public List<string> Banners { get; } = new List<string>();

        public void OnBanner(string message, string languageTag)
        {
            Banners.Add(message);
        }
    }
}
