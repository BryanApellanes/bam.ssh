# bam.ssh

A production-quality SSH client and server protocol stack implemented from scratch in modern C# targeting .NET 10. Part of the [Bam Toolkit](https://github.com/BryanApellanes/bamtk).

No wrapping of existing SSH implementations: no OpenSSH P/Invoke, no libssh/libssh2. The SSH protocol is implemented directly against the RFCs using .NET cryptographic primitives (BouncyCastle only where the BCL has no equivalent — see `docs/decisions.md`).

**Status: feature-complete.** All 13 implementation phases are done — transport, key exchange, encryption, authentication, channels, high-level client and server, SFTP, SCP, port forwarding, and a performance pass — each with tests and a protocol walkthrough. **Start with the [documentation hub](docs/README.md) and the [getting-started guide](docs/guides/getting-started.md).**

## Goals

- **Full stack:** client, server, transport, key exchange, authentication, connection protocol/channels, port forwarding, SFTP, SCP, terminal support.
- **Native AOT compatible and trim-safe** on Windows, Linux, macOS, Android, and iOS (x64 + ARM64). No reflection, no `Reflection.Emit`, no dynamic proxies, no runtime code generation.
- **Modern cryptography only:** curve25519-sha256, ecdh-sha2-nistp256, diffie-hellman-group14-sha256 key exchange; Ed25519 / ECDSA P-256 / RSA SHA-2 host keys; chacha20-poly1305 / AES-GCM / AES-CTR encryption; HMAC-SHA2 MACs. No MD5; SHA-1 only where interoperability absolutely requires it.
- **High performance:** `Span<T>` / `System.IO.Pipelines` / `ArrayPool` throughout; hot-path allocation is near-zero and payload-independent (see [performance.md](docs/protocol/performance.md)); async-only with `CancellationToken` on every API.
- **Hardened:** strict packet validation; defenses against replay, malformed/oversized packets, flooding, resource exhaustion, timing attacks, integer overflow, and protocol downgrade.

## Architecture

Layering is strict and one-directional:

```
Applications
    ↓
App services           bam.ssh.sftp, bam.ssh.scp, bam.ssh.forwarding
Client / Server        bam.ssh.client, bam.ssh.server
    ↓
Connection             bam.ssh.connection (channels, flow control, exec/shell/subsystem, PTY, global requests)
    ↓
Authentication         bam.ssh.authentication (password, publickey, keyboard-interactive; pluggable)
    ↓
Transport              bam.ssh.transport (version exchange, kex, encryption, MAC, rekeying)
    ↓
Packet Layer           bam.ssh.common (framing, binary encoding, sequence numbers, buffers)
    ↓
Network Stream         abstract transport: TCP, Unix sockets, custom
```

A rendered version of this diagram, plus a connect→auth→exec sequence diagram, is in the [documentation hub](docs/README.md).

## Projects

| Project | Root namespace | Purpose |
|---|---|---|
| `bam.ssh.common` | `Bam.Ssh` | Protocol primitives, packet encoder/decoder, binary serialization, framing, sequence numbers, buffer pooling |
| `bam.ssh.transport` | `Bam.Ssh.Transport` | Version negotiation, key exchange, packet encryption/authentication, compression, rekeying |
| `bam.ssh.authentication` | `Bam.Ssh.Authentication` | Password, public key, keyboard-interactive; pluggable method model |
| `bam.ssh.connection` | `Bam.Ssh.Connection` | Channels, windows, flow control, exec/shell/subsystem, env, PTY, signals, exit status |
| `bam.ssh.terminal` | `Bam.Ssh.Terminal` | Terminal abstraction |
| `bam.ssh.sftp` | `Bam.Ssh.Sftp` | SFTP v3 protocol (OpenSSH-compatible), `SftpClient`/`SftpServer`, `ISftpFileSystem` |
| `bam.ssh.scp` | `Bam.Ssh.Scp` | SCP `scp1` binary protocol, `ScpClient`, server exec handler |
| `bam.ssh.forwarding` | `Bam.Ssh.Forwarding` | TCP/IP port forwarding (local/remote/dynamic SOCKS), socket↔channel bridge |
| `bam.ssh.client` | `Bam.Ssh.Client` | High-level `SshClient` API |
| `bam.ssh.server` | `Bam.Ssh.Server` | High-level `SshServer` API |
| `bam.ssh.tests` | `Bam.Ssh.Tests` | bam.test unit/integration/fuzz/property tests |
| `bam.ssh.benchmarks` | `Bam.Ssh.Benchmarks` | Performance benchmarks |
| `bam.ssh.samples` | `Bam.Ssh.Samples` | Console samples |

## API sketch

Client — connect, authenticate, run a command (full recipes in the [getting-started guide](docs/guides/getting-started.md)):

```csharp
await using SshClient client = new SshClient();          // known_hosts TOFU trust by default
await client.ConnectAsync("example.com", 22);
await client.AuthenticateWithPasswordAsync("alice", "s3cret");
SshCommandResult result = await client.ExecuteAsync("uname -a");
Console.WriteLine(result.StandardOutputText);

// SFTP, SCP, and port forwarding ride the same connection:
await using SftpClient sftp = await SftpClient.OpenAsync(await client.OpenSessionChannelAsync());
await sftp.UploadAsync("/incoming/readme.txt", "hello"u8.ToArray());
await using LocalPortForwarder fwd = await client.ForwardLocalPortAsync(5432, "db.internal", 5432);
```

Server — add a host key, choose auth, map handlers, listen:

```csharp
await using SshServer server = new SshServer();
server.AddHostKey(hostKey);
server.UsePasswordAuthentication(passwordPolicy);
server.MapExec(async (context, ct) => { await context.WriteAsync("hi\n", ct); await context.ExitAsync(0, ct); });
server.MapSftp(new PhysicalSftpFileSystem("/srv/sftp"));
server.EnableTcpForwarding();
await server.StartAsync(new IPEndPoint(IPAddress.Any, 2222));
```

## Building and testing

This repository is a submodule of [bamtk](https://github.com/BryanApellanes/bamtk) at `submodules/bam.ssh` and builds as part of `bamtk.sln`. The test project uses the bamtk `bam.test`/`bamtest` framework and is discovered and run by the bamtk `run-tests.sh` orchestrator. The core libraries (`bam.ssh.common` through `bam.ssh.server`) have **zero dependencies outside this repository** so they remain Native AOT / trim-safe and portable; only the test project references bamtk framework projects.

## Documentation

- **[`docs/README.md`](docs/README.md)** — documentation hub: architecture diagrams, and every per-layer protocol walkthrough in reading order.
- **[`docs/guides/getting-started.md`](docs/guides/getting-started.md)** — copy-pasteable recipes (client, host-key trust, auth, shell, SFTP, SCP, forwarding, server).
- [`docs/project-plan.md`](docs/project-plan.md) — implementation plan, phase status, and the RFC map.
- [`docs/decisions.md`](docs/decisions.md) — design decision log D-001…D-020 (the *why* behind choices).
- [`docs/protocol/`](docs/protocol/) — the twelve layer walkthroughs, from the packet layer through performance.

## License

MIT
