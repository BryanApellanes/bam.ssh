# Client (Phase 7)

`bam.ssh.client` (namespace `Bam.Ssh.Client`) is the developer-facing façade. `SshClient` composes the
whole stack — transport, key exchange, host-key trust, authentication, and the connection/channel layer —
behind an `HttpClient`-shaped API, so an application never has to wire the layers together by hand.

## The shape of a session

```csharp
await using SshClient client = new SshClient();
await client.ConnectAsync("example.com");                 // version exchange + key exchange + host-key trust
await client.AuthenticateWithPasswordAsync("alice", pw);  // RFC 4252 user authentication
SshCommandResult result = await client.ExecuteAsync("uname -a");
Console.WriteLine(result.StandardOutputText);             // "Linux …"
Console.WriteLine(result.ExitCode);                       // 0
```

`SshClient` is a small state machine — **Created → Connected → Authenticated → Disposed** — and each
operation checks it is in the right state (running a command before authenticating throws
`SshConnectionStateException`).

- **`ConnectAsync`** builds an `SshTransport` (over TCP, or any injected `ISshDuplexStream` — a Unix
  socket, a custom transport, or a test loopback), runs version exchange and key exchange, then makes the
  **host-key trust decision** (below) before returning. No credentials have been sent yet.
- **`AuthenticateAsync`** drives `SshUserAuthenticator` with Phase 5 `ISshAuthenticationMethod`s (the
  `AuthenticateWithPasswordAsync` / `AuthenticateWithPublicKeyAsync` overloads are thin wrappers). On
  success it constructs the `SshConnection` and, if configured, starts keep-alive.
- **`ExecuteAsync`** opens a session channel, sends `exec`, drains stdout and stderr concurrently to end
  of stream, captures `exit-status`, and returns an `SshCommandResult`.
- **`OpenShellAsync`** optionally requests a PTY then starts a shell, returning the raw session channel
  for interactive I/O. **`OpenSessionChannelAsync`** exposes a bare channel for advanced use.

## Host-key trust (the D-010 deferral)

Key exchange only proves the server's host-key *signature* is valid — not that the key should be
*trusted*. That decision lives here, as a pluggable `ISshHostKeyVerifier` invoked after key exchange and
before authentication; returning false aborts with `SshHostKeyRejectedException`.

- **`KnownHostsHostKeyVerifier`** — real OpenSSH `known_hosts` behavior:
  - matches the host against each entry: plain patterns, the `[host]:port` form for non-default ports,
    and HMAC-SHA1 **hashed** entries (`|1|salt|hash`);
  - a byte-identical stored key of the right type is **trusted**;
  - a stored key of the same type that **differs** is **rejected** as a possible man-in-the-middle — it
    is never silently overwritten;
  - a host with no stored key is **appended and trusted** in TOFU mode, or **rejected** in strict mode.
- **`CallbackHostKeyVerifier`** — delegate the decision to your own prompt or policy.
- **`AcceptAllHostKeyVerifier`** — trusts everything; insecure, for tests/first-run only (named bluntly
  so it stands out in review).

The **default** (when you don't pass a verifier) is TOFU over `~/.ssh/known_hosts`, matching interactive
`ssh`'s first-connect behavior. Choose `KnownHostsHostKeyVerifier.Strict(path)` for production servers
whose keys you already pin.

> The hashed-host match uses HMAC-SHA1 because that is exactly the construction OpenSSH's
> `HashKnownHosts` uses — the hash only obscures which hosts you have visited, it is not a security
> primitive. All real hashing in the stack is SHA-2.

## Keep-alive

Set `SshClientOptions.KeepAliveInterval` to have the client periodically send a
`keepalive@openssh.com` global request once authenticated. Per OpenSSH convention the request sets
`want_reply`, and *either* a success or a failure reply proves the peer is alive; only the absence of a
reply signals a dead connection. Keep-alive is disabled by default.

## What is deferred

`UploadAsync`/`DownloadAsync` (SFTP, Phase 9), SCP (Phase 10), and port forwarding (Phase 11) are added
to `SshClient` in their phases; the full terminal abstraction (`bam.ssh.terminal`) is likewise later. The
server role is Phase 8.

See decision **D-014** in [decisions.md](../decisions.md).
