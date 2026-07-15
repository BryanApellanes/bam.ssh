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
