# SFTP (Phase 9)

`bam.ssh.sftp` (`Bam.Ssh.Sftp`) implements **SFTP version 3** — the file-transfer subsystem OpenSSH speaks —
as a protocol engine plus a client and a server, riding the Phase 6 channel byte streams and the Phase 8
`subsystem` seam. It is the first layer above the SSH connection: SFTP is "just" a request/response protocol
carried over a `session` channel that has started the `sftp` subsystem.

## Layering

The engine is decoupled from the SSH façades by a one-method-each seam, `ISftpChannel` (ReadAsync/WriteAsync).
`bam.ssh.sftp` references only `bam.ssh.connection`. The client wraps an `SshChannel`
(`SshChannelSftpChannel`); the server wraps a served `SshServerCommandContext` (a thin adapter in
`bam.ssh.server`, which already references `bam.ssh.sftp`). So the same protocol code runs in a fast in-memory
loopback test and in production over a real encrypted channel.

## Wire format

Every SFTP message is a big-endian `uint32` length, a one-byte type, then the payload; `SftpMessageChannel`
frames these over an `ISftpChannel` (pooled buffers, an oversized-length guard). Requests carry a `uint32`
request id after the type; responses echo it. The types are the version-3 set: `INIT`/`VERSION`,
`OPEN`/`CLOSE`/`READ`/`WRITE`, `OPENDIR`/`READDIR`, `STAT`/`LSTAT`/`FSTAT`/`SETSTAT`,
`MKDIR`/`RMDIR`/`REMOVE`/`RENAME`/`REALPATH`, and the `STATUS`/`HANDLE`/`DATA`/`NAME`/`ATTRS` responses. The
`ATTRS` structure (`SftpFileAttributes`) is a presence-flag word followed by only the present fields, so
"not reported" is distinct from "zero".

Because `SshWireReader`/`SshWireWriter` are ref structs that cannot cross an `await`, both the client and the
server **parse each message synchronously into a plain request/response object first**, then do the async work
— the same discipline the connection layer uses.

## Client

```csharp
SshSessionChannel channel = await sshClient.OpenSessionChannelAsync();
await using SftpClient sftp = await SftpClient.OpenAsync(channel);   // starts the subsystem + INIT/VERSION
await sftp.UploadAsync("/remote/report.csv", bytes);
byte[] data = await sftp.DownloadAsync("/remote/report.csv");
IReadOnlyList<SftpName> entries = await sftp.ListDirectoryAsync("/remote");
```

`SftpClient` performs the INIT/VERSION handshake, then runs **one background reader loop** that correlates
each response to the pending request by id (mirroring `SshConnection`'s single-reader rule), so operations can
be outstanding without racing on the channel. It exposes the SFTP primitives (`OpenFileAsync`,
`ReadFileAsync`, `WriteFileAsync`, `GetAttributesAsync`, `ListDirectoryAsync`, `MakeDirectoryAsync`,
`RemoveFileAsync`, `RemoveDirectoryAsync`, `RenameAsync`, `GetRealPathAsync`) and the high-level
`UploadAsync`/`DownloadAsync` that chunk transfers. A non-`OK` status surfaces as `SftpStatusException`
carrying the `SftpStatusCode`.

## Server and the virtual filesystem

`SftpServer` serves one channel from an `ISftpFileSystem`: INIT→VERSION, then a request loop that dispatches
to the filesystem and keeps a handle table mapping opaque SFTP handles to open file/directory handles. It
processes one request at a time, which keeps the filesystem free of concurrency concerns and the outbound
stream serialized. A filesystem signals errors by throwing `SftpStatusException` with a specific code, which
the engine turns into the matching `STATUS` response; unknown request types are answered `OP_UNSUPPORTED`.

`ISftpFileSystem` is the pluggable backing store. Two implementations ship:

- **`InMemorySftpFileSystem`** — a dictionary tree of directories and byte-array files. Deterministic,
  disk-free, fully sandboxed; ideal for tests and ephemeral servers.
- **`PhysicalSftpFileSystem`** — maps the SFTP namespace onto a real OS directory subtree, **jailed** to a
  root: paths are canonicalized (so `..` can never climb above the root — the primary sandbox) and a
  defense-in-depth `IsWithinRoot` check refuses anything that still resolves outside. Positional reads/writes
  use `RandomAccess`, so a handle needs no file-pointer state.

Wire it into a server with the `MapSftp` extension:

```csharp
server.UsePasswordAuthentication(policy);
server.MapSftp(new PhysicalSftpFileSystem("/srv/files"));   // or a per-session factory
await server.StartAsync(endpoint);
```

## What Phase 9 proves

The crown-jewel tests run a production `SftpClient` over the production `SshClient` ↔ `SshServer` loopback
(`MapSftp`) and perform full round-trips — `mkdir` → upload → list → download → stat → realpath → rename →
remove → rmdir — against **both** the in-memory and the physical filesystem, confirming the bytes land on disk
and that a path attempting to escape the physical root is blocked. Focused unit tests cover the ATTRS codec,
path canonicalization, and the in-memory filesystem's operations and error mapping.

## Deferred

- **SFTP versions 4–6** and their richer attribute model; this is v3, the OpenSSH-compatible baseline.
- **SYMLINK / READLINK** and vendor **extended** requests are answered `OP_UNSUPPORTED`.
- **Interop with real OpenSSH `sftp`/`sshd`** remains the standing deferred interop checkpoint.
- Recursive directory upload/download helpers (SCP recursion is Phase 10).
