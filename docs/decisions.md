# bam.ssh Decision Log

Records *why* decisions were made, not just what they are. Append-only; newest entries at the bottom.

## D-001: Core libraries have zero dependencies outside this repository

**Date:** 2026-07-15
**Decision:** `bam.ssh.common` through `bam.ssh.server` reference only each other. No bamtk framework references, no third-party packages in the core (BouncyCastle admitted only if a required algorithm has no BCL equivalent — see D-004). Only `bam.ssh.tests` references bamtk projects (`bam.test`, `bam.console`).
**Why:** Native AOT + trim-safety across five OSes is a hard requirement; every dependency is a compatibility risk. It also keeps the stack suitable for standalone open-source publication while still building inside `bamtk.sln`.

## D-002: Root namespace `Bam.Ssh` is owned by `bam.ssh.common`; top-level API types also live in `Bam.Ssh`

**Date:** 2026-07-15
**Decision:** The common/primitives assembly uses root namespace `Bam.Ssh` (not `Bam.Ssh.Common`). The flagship API types `SshClient` and `SshServer` are declared in namespace `Bam.Ssh` even though they compile into `bam.ssh.client` / `bam.ssh.server`. Layer-specific types live in `Bam.Ssh.Transport`, `Bam.Ssh.Authentication`, `Bam.Ssh.Connection`, etc.
**Why:** Mirrors BCL idiom (e.g. `HttpClient` in `System.Net.Http`): application developers get the whole developer-facing surface with a single `using Bam.Ssh;`, while protocol internals stay in layer namespaces. C# namespaces may span assemblies, so this costs nothing.

## D-003: Strict layering enforced by project references

**Date:** 2026-07-15
**Decision:** Project references encode the directive's layering exactly: transport → common; authentication → transport; connection → authentication; sftp/scp → connection; terminal → common; client/server → connection + sftp + scp + terminal. No project may reference upward or sideways beyond this.
**Why:** Making the layering a compile-time property (rather than a convention) means a violation is a build error, not a review finding.

## D-004: BCL cryptography first; BouncyCastle only for gaps

**Date:** 2026-07-15
**Decision:** All cryptography uses `System.Security.Cryptography` where the BCL provides the algorithm. Known BCL coverage: X25519/Ed25519 (`System.Security.Cryptography` net10 has `X25519`/`Ed25519` support — verify at Phase 3; fall back to BouncyCastle 2.6.x if absent on any target platform), ECDH P-256, DH group14 via `BigInteger` or BouncyCastle, AES-GCM (`AesGcm`), AES-CTR (composed from `Aes` ECB + counter, since BCL has no CTR mode), ChaCha20-Poly1305 (`ChaCha20Poly1305` — note: OpenSSH's `chacha20-poly1305@openssh.com` uses a two-key construction that requires a raw ChaCha20 keystream, which the BCL does NOT expose; this will need a managed ChaCha20 implementation or BouncyCastle — decide at Phase 4), HMAC-SHA2, SHA-2 family, `RandomNumberGenerator`.
**Why:** The directive mandates .NET primitives where feasible with BouncyCastle as the documented fallback. bam.encryption already depends on BouncyCastle 2.6.2, so precedent exists in the toolkit if needed.

## D-005: Test project uses bam.test/bamtest (not xUnit)

**Date:** 2026-07-15
**Decision:** `bam.ssh.tests` is a console exe on the bamtk `bam.test` framework (`UnitTestMenuContainer`, `[UnitTest]`), discovered by the bamtk `run-tests.sh`/`bamtest` orchestrator, per the toolkit-wide convention. Confirmed by project owner 2026-07-15.
**Why:** Toolkit consistency; bamtest aggregates coverage across the whole bamtk solution. The core libraries stay framework-free (D-001), so this does not affect AOT goals.

## D-006: Compression negotiated but deferred

**Date:** 2026-07-15
**Decision:** The transport advertises and accepts only `none` compression initially. The negotiation and packet pipeline include the seam for `zlib`/`zlib@openssh.com` (payload transform between framing and encryption), but no compressor ships until a later pass.
**Why:** Compression is optional in RFC 4253, rarely beneficial on modern links, and `zlib@openssh.com` (delayed compression) adds auth-state coupling. Deferring it keeps Phase 2–4 focused; the seam prevents a later retrofit.

## D-007: `System.Diagnostics.DiagnosticSource` (ActivitySource) is the one non-BCL-core assembly admitted to the core libraries

**Date:** 2026-07-15
**Decision:** The core libraries stay dependency-free (D-001) with a single exception: `System.Diagnostics.DiagnosticSource`, used for `ActivitySource`/`Activity` tracing spans (`SshActivitySource` in `bam.ssh.common`). Logging uses the framework-free `ISshLogger` seam instead of any logging package.
**Why:** The directive explicitly requires `ActivitySource` and OpenTelemetry support. `System.Diagnostics.DiagnosticSource` ships in the .NET shared framework, is trim/AOT-annotated by Microsoft, and needs no `PackageReference` (it resolved at build with `IsAotCompatible`/`TreatWarningsAsErrors` on and zero warnings). Re-implementing tracing would be strictly worse than consuming the first-party, AOT-safe primitive. A logging *framework* (e.g. bamtk `bam.logging`) would break AOT/portability, so logging is abstracted behind `ISshLogger` and adapted only in the future client/server composition roots.

## D-008: Cipher applied around framing via a per-direction `ISshPacketCipher`; sequence numbers owned by the reader/writer, not the codec

**Date:** 2026-07-15
**Decision:** Encryption/MAC is a per-direction seam (`ISshPacketCipher`) that the Phase 2 `SshPacketWriter`/`SshPacketReader` apply around the Phase 1 encoder/decoder. `NonePacketCipher` is the cleartext identity used before key exchange. The seam exposes `Geometry` (drives padding), `MacLength`, `LengthPeekSize`, `TransformOutgoing`, `DecryptLength`, and `VerifyAndDecrypt` — enough for Phase 4's chacha20-poly1305 (encrypted length, 16-byte tag), AES-GCM (cleartext length, 16-byte tag), and AES-CTR+HMAC (cleartext length, separate MAC) without touching the send/receive loop. The send/receive `SshSequenceNumber` lives in the writer/reader (not the Phase 1 codec) because the MAC binds the sequence number to cipher state.
**Why:** Keeps framing, ciphering, and orchestration at one responsibility each and makes the Phase 4 swap a field assignment (`SwapCipher`/`ApplyKeys`) rather than a rewrite. The returned `SshIncomingPacket` owns a pooled copy of the payload (via the Phase 1 `SshRentedBuffer`) because the decoder's slice is only valid until the pipe advances — pooled, not `new byte[]`, to hold the near-zero-allocation line.

## D-009: BouncyCastle admitted to `bam.ssh.transport` for X25519 and Ed25519 only

**Date:** 2026-07-15
**Decision:** `BouncyCastle.Cryptography` 2.6.2 is referenced by `bam.ssh.transport` (Phase 3), used in exactly two places: `Curve25519KeyExchange` (X25519 agreement for curve25519-sha256) and `Ed25519HostKey` (ssh-ed25519 signature verification). Everything else cryptographic uses `System.Security.Cryptography`: `ECDiffieHellman` (ecdh-sha2-nistp256), `BigInteger` (diffie-hellman-group14-sha256, RFC 3526 group 14), `ECDsa` (ecdsa-sha2-nistp256 host keys), `RSA` (rsa-sha2-256/512 host keys), and the SHA-2 family. This is a documented, narrowly-scoped exception to D-001 (zero external dependencies in core libraries).
**Why:** Probed on the target machine: .NET 10's BCL exposes `ECDiffieHellman`, `AesGcm`, `ChaCha20Poly1305`, and `MLKem` but **no X25519 and no Ed25519**. The directive *requires* curve25519-sha256 and Ed25519, so the D-004 BouncyCastle fallback is unavoidable for those two primitives. BouncyCastle 2.6.x is pure-managed, reflection-free in these code paths, and Native AOT / trim compatible; `bam.encryption` already depends on the same package version. Confining the reference to `bam.ssh.transport` (which the directive designates as the home of key exchange and packet encryption) keeps the rest of the stack BCL-only. Note for Phase 4: OpenSSH's `chacha20-poly1305@openssh.com` uses a two-key construction requiring a raw ChaCha20 keystream that the BCL `ChaCha20Poly1305` does not expose, so that cipher will also need BouncyCastle (or a managed ChaCha20) — to be decided in Phase 4.

## D-010: Phase 3 produces key material; cipher activation and host-key trust are deferred

**Date:** 2026-07-15
**Decision:** `SshClientKeyExchange.PerformAsync` completes the full handshake (KEXINIT negotiation, agreement, signature verification, NEWKEYS) and returns `SshKeyExchangeResult` carrying the negotiated algorithms, the verified host key, the exchange hash, and `SshSessionKeys`. It does **not** call `SshTransport.ApplyKeys` — turning `SshSessionKeys` into live ciphers is Phase 4 — and it does **not** decide host-key *trust* (known_hosts/TOFU), only that the signature is cryptographically valid; trust policy is Phase 7. Keys are derived at a uniform 64-byte length; because RFC 4253 §7.2 derivation is a prefix relationship, Phase 4 slices the exact prefix each negotiated algorithm needs.
**Why:** Phase boundaries. Phase 3 owns the cryptographic handshake; Phase 4 owns ciphers; Phase 7 owns the client trust model. Surfacing the verified key and hash (rather than silently accepting or activating) keeps each concern in its phase without hiding the trust decision.
