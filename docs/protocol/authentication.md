# User Authentication Walkthrough (Phase 5)

How bam.ssh authenticates a user over the encrypted transport from Phases 1–4 (RFC 4252 user
authentication, RFC 4256 keyboard-interactive, RFC 8332/8709/5656 signature algorithms). Types live in
`bam.ssh.authentication` (namespace `Bam.Ssh.Authentication`). Rationale is in the Phase 5 design
([bam.ssh#9](https://github.com/BryanApellanes/bam.ssh/issues/9)) and decision D-012.

## Where authentication plugs in

Once key exchange (Phase 3) has produced a session identifier and the transport is encrypted (Phase 4),
`SshUserAuthenticator` runs the RFC 4252 dialog over the same `SshTransport`. It is a **client-side**
authenticator; the server side (auth policy, credential stores) is Phase 8. The layer references only
`bam.ssh.transport`.

```
SERVICE_REQUEST("ssh-userauth")  ──▶
                                 ◀──  SERVICE_ACCEPT("ssh-userauth")
USERAUTH_REQUEST(user, "ssh-connection", method, …)  ──▶
                                 ◀──  USERAUTH_SUCCESS | USERAUTH_FAILURE(continue-list, partial) | BANNER | (60–79)
```

## The orchestrator and the conversation seam

`SshUserAuthenticator` owns the packet loop and tries a caller-supplied ordered list of
`ISshAuthenticationMethod` until one succeeds. It implements `ISshAuthenticationConversation` — the
narrow seam a method uses to send a request and read the next reply — so the generic replies are
handled once, centrally:

- **SSH_MSG_USERAUTH_SUCCESS (52)** → `SshAuthenticationReply` of kind `Success`; the dialog ends.
- **SSH_MSG_USERAUTH_FAILURE (51)** → kind `Failure` carrying the auths-that-can-continue name-list and
  the partial-success flag.
- **SSH_MSG_USERAUTH_BANNER (53)** → surfaced to the `ISshBannerSink` and transparently skipped; the
  loop reads the next reply.
- **Method-specific (60–79)** → kind `MethodSpecific`, handed to the running method to interpret (the
  same number means different things per method, so the numbers live in `SshUserAuthMessageNumber`, not
  the shared enum).

A method's `AttemptAsync` returns the **terminal** reply (Success or Failure); the orchestrator records
the continue-list from each failure and returns an `SshAuthenticationResult` naming the winning method
or, on exhaustion, the last continue-list.

## The methods

| Method | Fields sent | Method-specific handling |
|---|---|---|
| `none` (§5.2) | (none) | — probe; the failure's continue-list reveals acceptable methods |
| `password` (§8) | `boolean FALSE ‖ string password` | PASSWD_CHANGEREQ (60) reported as a failure (change flow deferred) |
| `publickey` (§7) | `boolean TRUE ‖ string alg ‖ string pubkey ‖ string signature` | — direct-sign, one round trip |
| `keyboard-interactive` (RFC 4256) | `string "" ‖ string submethods` | INFO_REQUEST (60) → prompts → INFO_RESPONSE (61) loop |

### publickey signing (RFC 4252 §7)

The signature proves possession of the private key and is bound to this session so it cannot be
replayed. The signed data is:

```
string    session identifier
byte      SSH_MSG_USERAUTH_REQUEST (50)
string    user name
string    "ssh-connection"
string    "publickey"
boolean   TRUE
string    public key algorithm name
string    public key blob
```

`PublicKeyAuthenticationMethod` builds this byte-for-byte the same way the conversation frames the
actual request header, signs it with an `ISshPrivateKey`, and sends the signature. The
`ISshPrivateKey` implementations (`Ed25519PrivateKey`, `EcdsaNistP256PrivateKey`, `RsaPrivateKey`) are
the **signing** counterparts of the transport's host-key **verifiers** and emit the identical
`string(algorithm) ‖ string(signature)` blob — so a real server verifies a bam.ssh client signature
with its standard algorithm implementation. Ed25519 signing uses BouncyCastle (no BCL Ed25519, D-012);
ECDSA and RSA use the BCL.

## Private-key files

`SshPrivateKeyReader.Read(pem, passphrase?)` detects the container and produces an `ISshPrivateKey`:

- **OpenSSH v1** (`-----BEGIN OPENSSH PRIVATE KEY-----`) — parsed by `OpenSshPrivateKeyParser` with the
  reused `SshWireReader`; ed25519, ecdsa-sha2-nistp256, and ssh-rsa are supported. **Encrypted** OpenSSH
  keys (bcrypt-pbkdf) are **not** supported this phase and raise `SshAuthenticationException` (D-012).
- **PKCS#8 / PEM** (plain or encrypted, and traditional PKCS#1 RSA / SEC1 EC) — RSA and ECDSA via the
  BCL (`ImportFromPem` / `ImportFromEncryptedPem`); Ed25519 via BouncyCastle. A bare `PRIVATE KEY`
  container (no algorithm in the label) is tried against each family in turn.

## Test coverage

bam.test unit tests (`bam.ssh.tests/Unit`) drive a `TestUserAuthServer` over the keyed
`LoopbackDuplexStream`; the server verifies publickey signatures with the **production** transport
host-key verifiers, proving wire-format parity:

- `password` success and rejection (continue-list surfaced).
- `publickey` success for ed25519, ecdsa-sha2-nistp256, and rsa; rejection of an unauthorized key.
- `keyboard-interactive` scripted challenge/response success.
- `none` probe surfacing continuable methods.
- Multi-method fallback (publickey → password) reporting the winning method.
- Banner delivery to the sink.
- Private-key parsing: ed25519/ecdsa/rsa from both OpenSSH v1 and PKCS#8/PEM parse and sign verifiably;
  encrypted OpenSSH v1 throws.

The test server is cancellable so a client that exhausts its methods cannot hang the server on a pending
receive (the Phase 4 loopback lesson). Real-OpenSSH interop is deferred until the bam.ssh server exists
(Phase 8).
