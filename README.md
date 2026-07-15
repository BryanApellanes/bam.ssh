# bam.ssh

A production-quality SSH client and server protocol stack implemented from scratch in modern C# targeting .NET 10. Part of the [Bam Toolkit](https://github.com/BryanApellanes/bamtk).

No wrapping of existing SSH implementations: no OpenSSH P/Invoke, no libssh/libssh2. The SSH protocol is implemented directly against the RFCs using .NET cryptographic primitives (BouncyCastle only where the BCL has no equivalent — see `docs/decisions.md`).

## Goals

- **Full stack:** client, server, transport, key exchange, authentication, connection protocol/channels, port forwarding, SFTP, SCP, terminal support.
- **Native AOT compatible and trim-safe** on Windows, Linux, macOS, Android, and iOS (x64 + ARM64). No reflection, no `Reflection.Emit`, no dynamic proxies, no runtime code generation.
- **Modern cryptography only:** curve25519-sha256, ecdh-sha2-nistp256, diffie-hellman-group14-sha256 key exchange; Ed25519 / ECDSA P-256 / RSA SHA-2 host keys; chacha20-poly1305 / AES-GCM / AES-CTR encryption; HMAC-SHA2 MACs. No MD5; SHA-1 only where interoperability absolutely requires it.
- **High performance:** `Span<T>` / `System.IO.Pipelines` / `ArrayPool` throughout; millions of packets without allocation; async-only with `CancellationToken` on every API.
- **Hardened:** strict packet validation; defenses against replay, malformed/oversized packets, flooding, resource exhaustion, timing attacks, integer overflow, and protocol downgrade.

## Architecture

Layering is strict and one-directional:

```
Applications
    ↓
Client / Server        bam.ssh.client, bam.ssh.server
    ↓
Connection             bam.ssh.connection (channels, flow control, exec/shell/subsystem, PTY)
    ↓
Authentication         bam.ssh.authentication (password, publickey, keyboard-interactive; pluggable)
    ↓
Transport              bam.ssh.transport (version exchange, kex, encryption, MAC, rekeying)
    ↓
Packet Layer           bam.ssh.common (framing, binary encoding, sequence numbers, buffers)
    ↓
Network Stream         abstract transport: TCP, Unix sockets, custom
```

## Projects

| Project | Root namespace | Purpose |
|---|---|---|
| `bam.ssh.common` | `Bam.Ssh` | Protocol primitives, packet encoder/decoder, binary serialization, framing, sequence numbers, buffer pooling |
| `bam.ssh.transport` | `Bam.Ssh.Transport` | Version negotiation, key exchange, packet encryption/authentication, compression, rekeying |
| `bam.ssh.authentication` | `Bam.Ssh.Authentication` | Password, public key, keyboard-interactive; pluggable method model |
| `bam.ssh.connection` | `Bam.Ssh.Connection` | Channels, windows, flow control, exec/shell/subsystem, env, PTY, signals, exit status |
| `bam.ssh.terminal` | `Bam.Ssh.Terminal` | Terminal abstraction |
| `bam.ssh.sftp` | `Bam.Ssh.Sftp` | SFTP protocol (OpenSSH-compatible where appropriate) |
| `bam.ssh.scp` | `Bam.Ssh.Scp` | SCP protocol |
| `bam.ssh.client` | `Bam.Ssh.Client` | High-level `SshClient` API |
| `bam.ssh.server` | `Bam.Ssh.Server` | High-level `SshServer` API |
| `bam.ssh.tests` | `Bam.Ssh.Tests` | bam.test unit/integration/fuzz/property tests |
| `bam.ssh.benchmarks` | `Bam.Ssh.Benchmarks` | Performance benchmarks |
| `bam.ssh.samples` | `Bam.Ssh.Samples` | Console samples |

## API sketch

```csharp
await using SshClient client = new SshClient();
await client.ConnectAsync(host);
await client.AuthenticateAsync(credentials);
SshCommandResult result = await client.ExecuteAsync("ls");
```

```csharp
SshServer server = new SshServer();
server.AddHostKey(hostKey);
server.UsePasswordAuthentication(validator);
server.MapShell(shellHandler);
await server.StartAsync();
```

## Building and testing

This repository is a submodule of [bamtk](https://github.com/BryanApellanes/bamtk) at `submodules/bam.ssh` and builds as part of `bamtk.sln`. The test project uses the bamtk `bam.test`/`bamtest` framework and is discovered and run by the bamtk `run-tests.sh` orchestrator. The core libraries (`bam.ssh.common` through `bam.ssh.server`) have **zero dependencies outside this repository** so they remain Native AOT / trim-safe and portable; only the test project references bamtk framework projects.

## Documentation

- `docs/project-plan.md` — running implementation plan and phase status
- `docs/decisions.md` — design decision log (the *why* behind choices)
- Architecture, protocol walkthroughs, and diagrams are added per-phase under `docs/`

## License

MIT
