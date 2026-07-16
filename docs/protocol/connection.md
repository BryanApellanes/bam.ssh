# Connection protocol (Phase 6, RFC 4254)

The connection layer (`bam.ssh.connection`, namespace `Bam.Ssh.Connection`) runs on top of the
authenticated, encrypted transport and multiplexes any number of independent **channels** over the
single byte stream. It is what turns a keyed session into something useful: running a command, opening
a shell, or driving a subsystem such as SFTP.

## The single reader / single writer rule

The transport is not thread-safe, so `SshConnection` is the **only** component that touches it:

- One **receive-dispatch loop** is the sole reader. It reads each packet, routes channel messages
  (90–100) to the addressed channel by *recipient channel id*, handles connection-generic messages
  (global requests 80–82), and drives re-keying (`KEXINIT`).
- One **outbound writer** is the sole writer. Every send — application data from any channel on any
  thread, control replies from the loop, global requests — is funnelled into one queue drained behind
  a `SemaphoreSlim`. Nothing else writes the transport.

This is the only race-free way to demultiplex a non-thread-safe stream, and it gives re-keying a single
safe place to pause application traffic (below).

```
          ┌──────────────────────── SshConnection ────────────────────────┐
 wire ──▶ │  dispatch loop (sole reader) ── route by recipient id ─┐       │
          │                                                        ▼       │
          │   SshChannel #0   SshChannel #1   SshChannel #2  ... (by id)   │
          │        │ data/ext pipes   ▲ window                            │
          │        ▼                  │                                    │
 wire ◀── │  outbound writer (sole writer) ◀── SendAsync / PostSend ──────┘
          └───────────────────────────────────────────────────────────────┘
```

## A channel

`SshChannel` is a transport-generic RFC 4254 channel — it knows nothing about "sessions":

- **Data streams.** Inbound `CHANNEL_DATA` and `CHANNEL_EXTENDED_DATA` (stderr) are written by the
  dispatch loop into two `System.IO.Pipelines` pipes and drained by the consumer through `ReadAsync` /
  `ReadExtendedAsync`. The pipe's own back-pressure is disabled; the **SSH receive window** bounds how
  much unread data can accumulate.
- **Flow control.** `SshSendWindow` meters outbound bytes against the peer's advertised window, chunking
  each write to the peer's maximum packet size and asynchronously waiting for a `CHANNEL_WINDOW_ADJUST`
  when the window is exhausted. `SshReceiveWindow` shrinks as data arrives and is replenished **only as
  the consumer actually drains it** — which is what stops one slow channel from head-of-line-blocking
  every other channel over the shared transport. When at least half the window has been freed the
  channel sends a `CHANNEL_WINDOW_ADJUST` back.
- **Requests.** `SendRequestAsync` sends a named `CHANNEL_REQUEST`; with `want_reply` it awaits the
  peer's `CHANNEL_SUCCESS`/`CHANNEL_FAILURE` (pending replies are a FIFO queue, since SSH answers
  requests in order). Inbound requests raise `RequestReceived`; the generic channel replies
  `CHANNEL_FAILURE` to any it is asked to answer.
- **Half-close.** `SendEofAsync` signals no-more-data; `CloseAsync` sends `CHANNEL_CLOSE`. The channel
  is torn down (and removed from the connection) once both sides have closed.

## A session channel

`SshSessionChannel` **composes** an `SshChannel` (composition, not inheritance) and adds the RFC 4254
§6 session semantics: `RequestPseudoTerminalAsync` (`pty-req`), `SetEnvironmentAsync` (`env`),
`ShellAsync`, `ExecAsync`, `SubsystemAsync`, `SendSignalAsync`, and `SendWindowChangeAsync`. It also
translates the peer's inbound `exit-status` and `exit-signal` requests into the `ExitStatusReceived` and
`ExitSignalReceived` events. Because it only composes the generic channel, Phase 11's port-forwarding
channels can reuse the same `SshChannel` with different open parameters and no session requests.

## Opening a channel

```csharp
await using SshConnection connection = new SshConnection(transport, sessionId);
SshSessionChannel session = await connection.OpenSessionChannelAsync();
if (await session.ExecAsync("uname -a"))
{
    byte[] buffer = new byte[4096];
    int read;
    while ((read = await session.Channel.ReadAsync(buffer)) > 0)
    {
        // consume stdout; this drain is what replenishes the receive window
    }
}
```

`OpenChannelAsync` allocates a local channel id, sends `CHANNEL_OPEN`, and awaits the peer's
`CHANNEL_OPEN_CONFIRMATION` (which supplies the peer's id, this side's send window, and the peer's
maximum packet size) or `CHANNEL_OPEN_FAILURE` (surfaced as an `SshChannelException`).

## Automatic re-keying (the Phase 4 deferral, resolved here)

Only the loop owner can safely renegotiate keys, so re-keying lives in `SshConnection`. When a byte or
time threshold is crossed, or the peer sends a `KEXINIT`, the connection:

1. holds the outbound send lock, so application/control sends **queue** for the duration (RFC 4253 §9
   forbids sending non-key-exchange messages once a `KEXINIT` has been sent);
2. runs `SshClientKeyExchange.RekeyAsync`, feeding it the key-exchange packets the loop reads through the
   new `ISshPacketSource` seam (`SshPacketQueue`) — the loop stays the only transport reader, and the
   existing Phase 3/4 key-exchange routine is reused unchanged apart from that optional parameter;
3. on completion, re-installs the fresh ciphers (via the transport's `ApplyKeys`, inside the kex
   routine), releases the send lock, and flushes the queued traffic.

The original session identifier is preserved across re-keys; inbound channel data that arrives
mid-re-key is still buffered normally — only *outbound* non-kex traffic is deferred.

## What is deferred

- **Accepting inbound `CHANNEL_OPEN`** (server role) is Phase 8: inbound opens raise `ChannelOpenReceived`
  and are rejected `UNKNOWN_CHANNEL_TYPE`, leaving a clean acceptance seam.
- **Forwarding channel types** (`direct-tcpip`, `forwarded-tcpip`, SOCKS) are Phase 11; the generic
  channel already carries their data, only the open-parameter helpers are pending.
- **Keep-alive scheduling** is Phase 7 (the client façade).

See decision **D-013** in [decisions.md](../decisions.md).
