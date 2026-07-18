# Port Forwarding (Phase 11)

`bam.ssh.forwarding` (`Bam.Ssh.Forwarding`) implements RFC 4254 §7 TCP/IP forwarding — **local** (`-L`),
**remote** (`-R`), and **dynamic SOCKS** (`-D`) — as a protocol-pure library over `bam.ssh.connection`, with a
thin server-side composition in `bam.ssh.server` and convenience methods on `SshClient`.

## The shape: one pump, four codecs, two roles

Forwarding is, at bottom, a single bidirectional byte pump — `SshChannelSocketBridge` — wired to a TCP
`Socket` on one end and an `SshChannel` on the other. Everything else is *which side owns the listener* and
*which side owns the `connect`*:

| Mode | Client | Server | Channel direction |
|---|---|---|---|
| Local `-L` | listens locally, opens `direct-tcpip`, bridges accepted socket → channel | accepts `direct-tcpip`, `connect`s the target, bridges channel → socket | client → server |
| Dynamic `-D` | listens locally, SOCKS-negotiates the target, opens `direct-tcpip` | same as `-L` server | client → server |
| Remote `-R` | sends `tcpip-forward`, accepts `forwarded-tcpip`, `connect`s the local target | accepts `tcpip-forward`, listens, opens `forwarded-tcpip` per connection | server → client |

So the connect side is a reusable `ISshChannelOpenHandler` and the listen side is a small `IAsyncDisposable`,
and the same bridge serves all six half-flows.

## Wire records

`ScpControlMessage`'s forwarding analogues are four tiny codecs:

- **`DirectTcpIpChannelRequest`** — `direct-tcpip` open data: `host-to-connect · port · originator-IP · originator-port`.
- **`ForwardedTcpIpChannelInfo`** — `forwarded-tcpip` open data: `connected-address · connected-port · originator-IP · originator-port`.
- **`TcpIpForwardRequest`** — `tcpip-forward`/`cancel-tcpip-forward` request data: `bind-address · bind-port`, plus the
  `uint32 bound-port` reply a port-0 request receives in `SSH_MSG_REQUEST_SUCCESS`.

Each `Parse` throws `SshForwardingException` on malformed bytes; each carries a `ToChannelOpenParameters`/`ToRequestData`
that produces exactly the bytes the connection layer sends.

## Connection-layer seams added this phase

The Phase 6 connection already multiplexed arbitrary channel types and sent global requests; Phase 11 added the
pieces needed to *accept* the peer-initiated half of forwarding on both roles:

- **Per-type channel-open registration** — `SshConnection.RegisterChannelOpenHandler(type, handler)` takes priority
  over the constructor's fallback handler. This is what lets the **client** accept inbound `forwarded-tcpip` opens
  (it has no fallback handler) and the **server** accept `direct-tcpip` opens *alongside* its `session` handler.
- **Global-request handler seam** — `ISshGlobalRequestHandler` + `SshGlobalRequestContext` (Accept/Reject with reply
  bytes), registered by name, so a server can service `tcpip-forward`. Unregistered names still auto-fail.
- **Global-request reply data** — `SendGlobalRequestWithReplyAsync` returns `SshGlobalRequestReply` (success + bytes),
  so a `tcpip-forward` with port 0 can read the server's chosen port from the success reply.

## The bridge

`SshChannelSocketBridge.RunAsync` runs two pumps over pooled buffers: socket→channel (socket EOF becomes
`channel.SendEofAsync`) and channel→socket (channel EOF becomes `socket.Shutdown(Send)`), then closes both once.
Every pump is fault-contained — a broken tunnel closes only its own socket and channel and never faults the shared
`SshConnection`.

## Client

`SshClient` exposes the three forwards directly:

- `ForwardLocalPortAsync(localPort, remoteHost, remotePort)` → `LocalPortForwarder`.
- `ForwardDynamicPortAsync(localPort)` → `DynamicPortForwarder` (SOCKS5 no-auth + SOCKS4/4a CONNECT).
- `ForwardRemotePortAsync(remotePort, localHost, localPort)` → `RemotePortForwarder` (its `BoundPort` is the
  server-chosen port when 0 was requested).

Disposing a forwarder stops listening; disposing a `RemotePortForwarder` also sends `cancel-tcpip-forward`. Several
remote forwards on one connection coexist: a single per-connection `forwarded-tcpip` acceptor routes each inbound open
to the right local target by the forwarded port.

## Server

`SshServer.EnableTcpForwarding(options?)` turns on forwarding acceptance for every served connection: `SshServerForwarding`
registers a `DirectTcpIpChannelAcceptor` (connect side of `-L`/`-D`) and a `TcpIpForwardListener` (listen side of `-R`) on
each connection, and is disposed with the session — tearing down any listeners the peer requested. Optional
`SshForwardingTargetFilter`/`SshForwardingBindFilter` policies veto disallowed targets and binds.

## What Phase 11 proves

The crown-jewel tests run over the production `SshClient` ↔ `SshServer` loopback (via `EnableTcpForwarding`) against real
TCP loopback echo targets:

- `-L`: a local forward to a remote echo target round-trips bytes;
- `-R`: the server binds port 0, returns the bound port, and a client to that server port round-trips to a client-side
  echo target;
- `-D`: a SOCKS5 CONNECT through the dynamic forwarder round-trips to the target.

Plus unit tests for the four wire codecs (encode↔parse, bound-port reply, malformed rejection) and the SOCKS negotiator
(SOCKS5 no-auth and SOCKS4a CONNECT, reply bytes, unknown-version rejection).

## Deferred

- X11 and agent forwarding, and StreamLocal/Unix-socket forwarding (`*@openssh.com`).
- SOCKS BIND/UDP-ASSOCIATE and SOCKS5 authentication methods beyond no-auth (other methods are refused with the proper
  SOCKS reply).
- A connect failure on the server side surfaces as an immediate channel close rather than `SSH_OPEN_CONNECT_FAILED`,
  because the channel-open handler must not block the dispatch loop — it accepts, then connects off the loop.
- Real-OpenSSH interop (deferred stack-wide).
