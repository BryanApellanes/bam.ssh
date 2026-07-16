# Key Exchange Walkthrough (Phase 3)

How bam.ssh establishes an authenticated, keyed session over the Phase 2 transport: algorithm
negotiation, key agreement, host-key signature verification, and key derivation (RFC 4253 §7–§8,
RFC 5656, RFC 8731). Types live in `bam.ssh.transport` (namespaces `Bam.Ssh.Transport`,
`…KeyExchange`, `…HostKeys`). Rationale is in the Phase 3 design
([bam.ssh#5](https://github.com/BryanApellanes/bam.ssh/issues/5)) and decisions D-009/D-010.

## Handshake sequence (client role)

```
1. C → S : SSH_MSG_KEXINIT (I_C)      2. S → C : SSH_MSG_KEXINIT (I_S)
3.        negotiate algorithms (§7.1, client-guided)
4. C → S : SSH_MSG_KEX_ECDH_INIT / KEXDH_INIT   (Q_C or e)
5. S → C : SSH_MSG_KEX_ECDH_REPLY  / KEXDH_REPLY (K_S, Q_S/f, signature over H)
6.        derive K; compute H; verify host-key signature over H  ← hard reject on failure
7. C → S : SSH_MSG_NEWKEYS          8. S → C : SSH_MSG_NEWKEYS
9.        session_id = H (first exchange); derive six directional keys (§7.2)
```

`SshClientKeyExchange.PerformAsync` drives this over `SshTransport` and returns
`SshKeyExchangeResult` (negotiated algorithms, verified host key, H, `SshSessionKeys`). It does **not**
activate ciphers (Phase 4 calls `ApplyKeys`) or decide host-key trust (Phase 7).

## Negotiation (RFC 4253 §7.1)

`SshKexInit` models the KEXINIT payload (16-byte cookie, ten name-lists, guess flag, reserved) and
round-trips to the exact wire bytes used as `I_C`/`I_S` in the hash. `SshAlgorithmNegotiation.Negotiate`
picks, in each category, the first *client*-preferred name the server also offers (via the Phase 1
`SshNameList.TryFindFirstCommon`); no overlap throws `SshKeyExchangeException`. The local offer comes
from `SshAlgorithmCatalog` (`SshAlgorithmNames` holds the constants).

## Key agreement

`ISshKeyExchangeAlgorithm` abstracts one method: generate an ephemeral key, publish a public value,
derive the shared secret. `PublicValueFormat` (string vs mpint) tells the hash and message code how to
encode public values.

| Method | Public value | Shared secret K | Crypto |
|---|---|---|---|
| curve25519-sha256 | 32-byte X25519 key (string) | 32-byte agreement as unsigned int | **BouncyCastle** X25519 (D-009) |
| ecdh-sha2-nistp256 | uncompressed point 0x04‖X‖Y (string) | agreed point X coordinate | BCL `ECDiffieHellman` |
| diffie-hellman-group14-sha256 | e = g^x mod p (mpint) | f^x mod p | BCL `BigInteger`, RFC 3526 group 14 |

All three reject degenerate peer values (all-zero X25519 output; off-curve points; f outside [2, p-2]).

## Exchange hash and derivation

`SshExchangeHash.Compute` builds `H = HASH(V_C ‖ V_S ‖ I_C ‖ I_S ‖ K_S ‖ Q_C ‖ Q_S ‖ K)` — version
strings, KEXINIT payloads, and host key as SSH strings; public values as strings (ECDH) or mpints
(DH); K always as an mpint (reusing the Phase 1 `SshMpint` minimal-form rules). `V_C`/`V_S` are the raw
identification bytes the Phase 2 `SshVersionExchangeResult` captured. `SshKeyDerivation.DeriveKey`
implements the §7.2 chain `K1 = HASH(K‖H‖letter‖session_id)`, extended by `Kn = HASH(K‖H‖K1‖…)` when a
key exceeds one digest — a *prefix* relationship, so Phase 4 slices what each cipher needs from the
uniform 64-byte outputs in `SshSessionKeys`.

## Host keys

`SshHostKeyParser.Parse` reads the K_S blob's leading algorithm name and builds an `ISshHostKey` that
verifies a signature over H:

| Algorithm | Key blob | Signature | Crypto |
|---|---|---|---|
| ssh-ed25519 | name ‖ 32-byte key | name ‖ 64-byte sig | **BouncyCastle** Ed25519 (D-009) |
| ecdsa-sha2-nistp256 | name ‖ "nistp256" ‖ point | name ‖ (mpint r ‖ mpint s) | BCL `ECDsa`, SHA-256 |
| ssh-rsa (rsa-sha2-256/512) | "ssh-rsa" ‖ mpint e ‖ mpint n | sig-name ‖ signature | BCL `RSA`, PKCS#1 v1.5 |

The RSA key blob type is always `ssh-rsa`; the *signature* name (`rsa-sha2-256`/`512`) selects the
digest. Legacy SHA-1 `ssh-rsa` signatures are rejected. `Fingerprint` is the OpenSSH `SHA256:base64`
form. A signature that does not verify is a hard connection rejection.

## Test coverage

17 bam.test unit tests: KEXINIT round-trip; §7.1 negotiation (client-preference selection, no-overlap
rejection); both-sides agreement for all three methods (real key pairs, asserting identical secrets);
exchange-hash determinism and input sensitivity; §7.2 derivation (length, determinism, the prefix
relationship, the extension block); host-key verification for ed25519 / ecdsa-p256 / rsa-sha2-256 /
rsa-sha2-512 (real signatures verify; tampered hash or signature rejected; fingerprint format); and a
full client↔server handshake over `LoopbackDuplexStream` against a test responder using the same
primitives, proving both sides derive identical session keys — plus the bad-signature rejection path.
Real-OpenSSH interop is a Phase 4 checkpoint (once packets are actually encrypted).
