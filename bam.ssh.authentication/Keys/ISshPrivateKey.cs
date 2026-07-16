using Bam.Ssh.Transport;

namespace Bam.Ssh.Authentication;

/// <summary>
/// A client private key that signs the session-bound authentication blob for publickey authentication
/// (RFC 4252 §7). This is the signing counterpart to the transport's <c>ISshHostKey</c> (which only
/// verifies): the public-key blob and signature blob produced here use the identical
/// <c>string(algorithm) || string(signature)</c> wire encoding a server verifies, so a signature from
/// this type is accepted by the matching transport host-key verifier. Because it exposes exactly the
/// members of <see cref="ISshHostKeySigner"/>, the same key can also serve as a server host key
/// (Phase 8) without any adaptation.
/// </summary>
public interface ISshPrivateKey : ISshHostKeySigner
{
}
