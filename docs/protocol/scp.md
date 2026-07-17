# SCP (Phase 10)

`bam.ssh.scp` (`Bam.Ssh.Scp`) implements the classic **SCP binary protocol** (`scp1`) — the wire a remote
`scp -t` (receive) and `scp -f` (send) still speak — as a protocol engine plus a client and a server-side
handler. Unlike SFTP, SCP is not a subsystem: it rides an ordinary `exec` of the remote `scp` program, and
each transfer is one such `exec` channel.

## The symmetry that shapes the design

SCP has one profound simplification: whichever side is *sending* file bytes plays the **source** role and
whichever is *receiving* plays the **sink** role, and the mapping to client/server simply flips between
upload and download. The only handshake asymmetry — who sends the very first `\0` acknowledgement — collapses
too, because **the sink always sends the first ack and the source always reads it first**, in both directions:

| Operation | Initiator (client) | Remote (`exec`) | Source | Sink |
|---|---|---|---|---|
| Upload | runs `scp -t path` | receives | client | server |
| Download | runs `scp -f path` | sends | server | client |

So the whole protocol is two role engines, reused on both ends:

- **`ScpSender`** (source) — streams `C`/`D`/`E` records and file data from an `ISftpFileSystem`. Used by the
  client's upload and the server's `scp -f`.
- **`ScpReceiver`** (sink) — receives records and data into an `ISftpFileSystem`, following OpenSSH's
  directory-stack placement. Used by the server's `scp -t` and the client's download.

Client-upload and server-source are *the same code*; so are client-download and server-sink.

## Layering

The engines ride a one-method-each seam, `IScpChannel` (ReadAsync/WriteAsync), so `bam.ssh.scp` references
only `bam.ssh.connection` (plus `bam.ssh.sftp` for the store abstraction). The client wraps an `SshChannel`
(`SshChannelScpChannel`); the server wraps a served `SshServerCommandContext` (`SshServerCommandContextScpChannel`,
a thin adapter in `bam.ssh.server`, which already references `bam.ssh.scp`). This mirrors Phase 9's
`ISftpChannel` decoupling exactly.

## Wire format

SCP is a line-and-binary protocol, not a length-framed one, so — unlike SFTP — it needs no
synchronous-parse-before-await dance (there is no `SshWireReader`/`SshWireWriter` ref struct in play).
`ScpProtocol` owns the byte grammar over an `IScpChannel`:

- **Acknowledgements** — a single byte: `0x00` success, `0x01` warning, `0x02` fatal (the latter two followed
  by a newline-terminated message). `ReadAckAsync` throws `ScpException` carrying the message on non-zero.
- **Control lines** — newline-terminated records the source sends:
  - `C<mode> <size> <name>` — a file, followed by exactly `<size>` data bytes then a trailing `0x00`.
  - `D<mode> 0 <name>` — enter a directory (recursive); entries follow until the matching `E`.
  - `E` — leave the current directory.
  - `T<mtime> 0 <atime> 0` — timestamps for the next entry (with `-p`).
- **File data** — exactly `<size>` raw bytes, copied through a pooled `ArrayPool<byte>` chunk buffer.

`ScpControlMessage.Parse`/`Format*` handle the record grammar (octal mode, decimal size, names that may
contain spaces); `ScpCommand.Parse` handles the remote command line (`-t`/`-f`, bundled flags like `-rt`,
`-r`, `-p`, and single/double-quoted paths).

## Client

`ScpClient(SshConnection)` opens **one session channel per transfer**, requests `exec scp -t …` (upload) or
`exec scp -f …` (download), wraps the channel, and runs the matching engine:

- `UploadAsync(localFileSystem, localPath, remotePath, recursive, preserveTimes)` — the local side is an
  `ISftpFileSystem`, so the same client uploads from an in-memory tree or a jailed OS directory.
- `DownloadAsync(localFileSystem, remotePath, localPath, recursive, preserveTimes)` — receives into the local
  filesystem, honoring the classic scp rename (a single top-level entry becomes `localPath` itself; into an
  existing directory, entries are placed inside by name).

When the transfer completes the client sends EOF and closes the channel (benign if the peer already closed).

## Server and the virtual filesystem

`SshServer.MapScp(ISftpFileSystem)` — and the per-session `MapScp(Func<SshServerCommandContext, ISftpFileSystem>)`
overload — registers the **exec** handler that services a peer's `scp`. Because SCP has no subsystem name, it
claims the server's single exec handler; a non-`scp` exec is answered with an error on stderr and a non-zero
exit. The handler parses the command line with `ScpCommand`, then runs `ScpReceiver` (for `-t`) or `ScpSender`
(for `-f`) over the same `ISftpFileSystem` the SFTP subsystem uses — `InMemorySftpFileSystem` or the
path-jailed `PhysicalSftpFileSystem`. A failure mid-transfer sends an SCP fatal-error record (`0x02`) to the
peer, writes the reason to stderr, and exits non-zero.

## What Phase 10 proves

The crown-jewel tests run the production `ScpClient` over the production `SshClient` ↔ `SshServer` loopback
(via `MapScp`):

- a single file uploaded to the server and downloaded back matches byte-for-byte, against both the in-memory
  and the physical (path-jailed) filesystems, with the on-disk variant asserting the files really land on each
  side's disk;
- a nested directory tree survives a recursive upload and a recursive download (top-level and nested files
  restored);
- a download of a missing remote path surfaces `ScpException` (the server's `0x02` fatal record, decoded by the
  sink).

## Deferred

- The modern SFTP-tunneled `scp` (newer OpenSSH `scp` optionally rides the SFTP subsystem) — this phase
  implements the traditional `scp1` binary protocol that `scp -t`/`scp -f` speak.
- Remote-path glob/wildcard expansion (the server services an explicit path).
- Preserve-mode fidelity beyond permissions + mtime/atime (no uid/gid, no ACLs).
- Real-OpenSSH interop testing (deferred stack-wide).
