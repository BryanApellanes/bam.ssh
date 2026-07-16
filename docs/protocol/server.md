# Server (Phase 8)

`bam.ssh.server` (namespace `Bam.Ssh.Server`) is the peer of the Phase 7 client. `SshServer` composes the
whole stack in **server role** — transport, key exchange (signing, not verifying), authentication policy,
and the connection/channel layer — behind a small configure-then-serve API, so an application never has to
wire the server layers together by hand. Together with `SshClient` this is the first point in the project
where two bam.ssh endpoints complete a real session end to end.

## The shape of a server

```csharp
await using SshServer server = new SshServer();
server.AddHostKey(new Ed25519PrivateKey(hostKeySeed));           // at least one host key is required
server.UsePasswordAuthentication(new MyPasswordPolicy());        // and at least one auth method
server.UsePublicKeyAuthentication(new MyAuthorizedKeysPolicy());
server.MapExec(async (context, ct) =>                            // handle `exec "…"`
{
    await context.WriteAsync($"you ran: {context.CommandLine}\n", ct);
    await context.ExitAsync(0, ct);
});
server.MapSubsystem("sftp", MySftpHandler);                      // handle `subsystem sftp`
await server.StartAsync(new IPEndPoint(IPAddress.Loopback, 0));  // bind + accept in the background
Console.WriteLine(server.ListenEndPoint);                        // e.g. 127.0.0.1:52344 (port 0 → ephemeral)
```

Configuration is **frozen** the moment serving begins (`StartAsync` or the first `AcceptAsync`): the host
keys, the auth policies, and the command map are captured once so every peer connection routes against the
same fixed set without locking. Adding a host key or handler after that throws `SshServerException`.

## The per-connection pipeline

`StartAsync` binds a TCP listener and runs a background accept loop; each accepted socket is wrapped and
handed to `AcceptAsync`, which is also public so a caller can serve one already-established transport (a
Unix socket, a custom transport, or a test loopback) directly. `AcceptAsync` runs the server role of every
layer in order:

1. **`SshTransport.ConnectAsync`** — the identification-string exchange (symmetric with the client).
2. **`SshServerKeyExchange.PerformAsync`** — the mirror of `SshClientKeyExchange`: it sends KEXINIT,
   negotiates against the client's, runs the chosen agreement using the client's public value, computes the
   exchange hash, and **signs** it with the host key (the client *verifies* the same blob). The server
   advertises only the host-key algorithms it actually holds, and the key matching the negotiated algorithm
   signs — so adding an Ed25519 and an RSA host key lets one server satisfy either client.
3. **`SshServerAuthenticator.AuthenticateAsync`** — accepts the `ssh-userauth` service, then loops on
   `USERAUTH_REQUEST`, delegating each attempt to the configured `ISshPasswordAuthenticator` /
   `ISshPublicKeyAuthenticator`. A publickey request is checked **two ways**: the policy authorizes the key
   *and* the request signature is verified against the session-id-bound §7 blob with the production
   transport verifier — so a forged signature is rejected even for an authorized key.
4. **`SshConnection`** — the same single-reader/single-writer connection the client uses, constructed with
   the server key exchange as its re-key driver and an **`SshServerSession` as its channel-open handler**.

`AcceptAsync` returns the authenticated `SshServerSession` once its connection is running; the TCP loop
holds it until the connection ends (`SshConnection.Completion`) and then disposes it.

## Accepting channels and running commands

`SshServerSession` is the connection's `ISshChannelOpenHandler`. It accepts `session` channels (and leaves
any other type unresolved, so the connection refuses it with `UNKNOWN_CHANNEL_TYPE`). On an accepted
channel it watches the inbound requests and maps each to a handler:

- `pty-req`, `env`, `window-change`, `signal` are acknowledged.
- `exec` / `shell` / `subsystem` resolve to the mapped `SshServerCommandHandler`. If one is mapped and the
  channel has not already started, the request is answered `CHANNEL_SUCCESS` and the handler runs **off the
  receive-dispatch loop** (so a blocking handler cannot stall other channels); an unmapped command or a
  second start on the same channel is answered `CHANNEL_FAILURE`.

A handler receives an `SshServerCommandContext` exposing who authenticated (`UserName`), what they asked to
run (`CommandType`, `CommandLine`, `SubsystemName`), and the three byte streams — `ReadAsync` (stdin),
`WriteAsync` (stdout), `WriteErrorAsync` (stderr). Returning from the handler finalizes the channel with an
`exit-status` of zero, then EOF, then CHANNEL_CLOSE; call `ExitAsync(code)` to report a different code. A
throwing handler reports exit status 1.

```csharp
server.MapSubsystem("echo", async (context, ct) =>
{
    byte[] buffer = new byte[4096];
    int n;
    while ((n = await context.ReadAsync(buffer, ct)) != 0)      // echo stdin → stdout
    {
        await context.WriteAsync(buffer.AsMemory(0, n), ct);
    }
    await context.ExitAsync(0, ct);
});
```

## What Phase 8 proves

The crown-jewel tests stand up a **production `SshServer`** and drive a **production `SshClient`** across one
loopback transport: a client connects, authenticates by password *and* (separately) by public key, and runs
a mapped `exec` whose stdout, stderr, and exit code flow back; wrong passwords and unauthorized keys are
refused with `SshAuthenticationException`; an unmapped command and a non-`session` channel are rejected; and
a subsystem streams stdin back out. This is the first end-to-end interoperability of two bam.ssh endpoints —
every layer built in Phases 1–7 now has a server counterpart exercised against its client.

## Deferred

- **Interop with real OpenSSH** (`sshd`/`ssh`) is still out of scope; Phase 8 proves our client ↔ our
  server. A dedicated interop checkpoint remains a later follow-on.
- **Limits and timeouts** beyond a concurrent-connection cap (handshake/auth/idle timeouts, per-user limits)
  are not yet implemented.
- **SFTP/SCP subsystem handlers** are Phases 9–10; Phase 8 provides the generic subsystem-handler seam they
  will plug into. Port forwarding (accepting `direct-tcpip`/`forwarded-tcpip` opens) is Phase 11.
