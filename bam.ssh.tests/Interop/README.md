# OpenSSH Interop Tests

Proves the bam.ssh stack interoperates with **stock OpenSSH** — not just with itself. Two directions, each gated by binary discovery and reported via bam.test's runtime skip API when the needed tools are absent (a skip is a first-class Skipped result with a reason, never a silent pass):

- **Direction A — `StockSshClientInteropShould`:** the production `SshServer` on an ephemeral loopback port, driven by the stock `ssh` / `sftp` / `scp` binaries as subprocesses. Needs the OpenSSH client tools (present on Windows via `C:\Windows\System32\OpenSSH` and on any Linux).
- **Direction B — `StockSshdInteropShould`:** the production `SshClient` against a stock `sshd -D` spawned on an ephemeral port with a workspace-generated config. Needs `sshd` (absent on a plain Windows box — runs on the Linux CI job, see bam.ssh#28, or under WSL).

## Harness types

| Type | Role |
|---|---|
| `OpenSshToolchain` | Locates `ssh`/`sshd`/`ssh-keygen`/`sftp`/`scp`; answers which directions can run |
| `InteropGate` | Skips a direction's tests (via `Bam.Test.Skip`) when its binaries are missing, or when `BAM_SSH_INTEROP=off` |
| `InteropWorkspace` | Disposable temp dir of fresh `ssh-keygen`-minted ed25519 host/user keys, `authorized_keys`, `known_hosts`, `sshd_config`; keys are also loaded into our endpoints via `SshPrivateKeyReader`, so real ssh-keygen output exercises the reader |
| `OpenSshClientCommand` | Builds and runs stock client invocations (argument lists, no shell; strict host-key checking; `BatchMode`; hard timeout) |
| `OpenSshDaemon` | Spawns `sshd -D -e -f <config>`, waits until listening, surfaces stderr on failure, kills on dispose |
| `SubprocessRunner` / `SubprocessResult` | Kill-on-timeout subprocess execution with captured output |

First-cut algorithm pinning (see D-021 and the resolved design in bam.ssh#27): `curve25519-sha256` + `chacha20-poly1305@openssh.com` + `ssh-ed25519` + publickey auth; expanding to the full kex/cipher/MAC/host-key matrix is a follow-on. Selector: `interop`.
