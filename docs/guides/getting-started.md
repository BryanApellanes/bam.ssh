# Getting started with bam.ssh

Copy-pasteable recipes for the common tasks. Every example uses the real public API. All operations are
async and take an optional `CancellationToken`; `SshClient` and `SshServer` are `IAsyncDisposable`.

- Client namespaces: `Bam.Ssh.Client`, `Bam.Ssh.Authentication`, `Bam.Ssh.Connection`.
- Server namespaces: `Bam.Ssh.Server`, `Bam.Ssh.Authentication`.
- SFTP/SCP/forwarding: `Bam.Ssh.Sftp`, `Bam.Ssh.Scp`, `Bam.Ssh.Forwarding`.

## Client: connect and run a command

```csharp
using Bam.Ssh.Client;

await using SshClient client = new SshClient();          // default: known_hosts TOFU trust
await client.ConnectAsync("example.com", 22);
await client.AuthenticateWithPasswordAsync("alice", "s3cret");

SshCommandResult result = await client.ExecuteAsync("uname -a");
Console.WriteLine(result.StandardOutputText);
Console.WriteLine($"exit code: {result.ExitCode}");
```

`SshCommandResult` exposes `ExitCode` (`int?`), `StandardOutput`/`StandardError` (`byte[]`), and the
`StandardOutputText`/`StandardErrorText` convenience decoders.

## Host-key trust

The host key is verified after key exchange and **before** any credential is sent. Choose a policy through
`SshClientOptions`:

```csharp
using Bam.Ssh.Client;

// Default (no options): OpenSSH known_hosts, trust-on-first-use at ~/.ssh/known_hosts.
SshClient tofu = new SshClient();

// Strict known_hosts: reject anything not already trusted.
SshClient strict = new SshClient(new SshClientOptions(
    KnownHostsHostKeyVerifier.Strict(KnownHostsHostKeyVerifier.DefaultPath())));

// Decide interactively.
SshClient callback = new SshClient(new SshClientOptions(
    new CallbackHostKeyVerifier((context, cancellationToken) =>
    {
        Console.WriteLine($"{context.Host}:{context.Port} key fingerprint {context.HostKey.Fingerprint}");
        return ValueTask.FromResult(true);
    })));

// Tests / trusted networks only — accepts any key. Insecure by name.
SshClient insecure = new SshClient(new SshClientOptions(AcceptAllHostKeyVerifier.Instance));
```

A changed key (possible MITM) is rejected under both TOFU and strict modes.

## Authentication

```csharp
using Bam.Ssh.Authentication;
using Bam.Ssh.Client;

// Password.
await client.AuthenticateWithPasswordAsync("alice", "s3cret");

// Public key — load an OpenSSH v1 or PKCS#8/PEM private key.
string keyText = await File.ReadAllTextAsync("/home/alice/.ssh/id_ed25519");
ISshPrivateKey key = SshPrivateKeyReader.Read(keyText);                 // add a passphrase argument if encrypted
await client.AuthenticateWithPublicKeyAsync("alice", key);

// Try several methods in order.
await client.AuthenticateAsync("alice", new ISshAuthenticationMethod[]
{
    new PublicKeyAuthenticationMethod(key),
    new PasswordAuthenticationMethod("s3cret"),
});
```

## Interactive shell with a PTY

```csharp
using Bam.Ssh.Connection;

SshSessionChannel shell = await client.OpenShellAsync(
    new SshPseudoTerminalParameters("xterm-256color", columns: 120, rows: 40));

await shell.Channel.WriteAsync("echo hello\n"u8.ToArray());
byte[] buffer = new byte[4096];
int read = await shell.Channel.ReadAsync(buffer);
```

## SFTP

Open a session channel, start the `sftp` subsystem via `SftpClient.OpenAsync`, then use the file operations.

```csharp
using Bam.Ssh.Sftp;

SshSessionChannel channel = await client.OpenSessionChannelAsync();
await using SftpClient sftp = await SftpClient.OpenAsync(channel);

await sftp.MakeDirectoryAsync("/incoming");
await sftp.UploadAsync("/incoming/readme.txt", "hello over sftp"u8.ToArray());
byte[] bytes = await sftp.DownloadAsync("/incoming/readme.txt");
IReadOnlyList<SftpName> listing = await sftp.ListDirectoryAsync("/incoming");
```

## SCP

```csharp
using Bam.Ssh.Scp;
using Bam.Ssh.Sftp;   // ISftpFileSystem is the local store abstraction, reused by SCP

ScpClient scp = new ScpClient(client.Connection);
ISftpFileSystem local = new PhysicalSftpFileSystem("/home/alice");     // jailed to this root

await scp.UploadAsync(local, "/report.pdf", "/var/incoming/report.pdf");
await scp.UploadAsync(local, "/project", "/var/incoming/project", recursive: true);
await scp.DownloadAsync(local, "/var/results", "/home/alice/results", recursive: true);
```

## Port forwarding

```csharp
using Bam.Ssh.Forwarding;

// Local (-L): listen locally, tunnel to a host reachable from the server.
await using LocalPortForwarder local = await client.ForwardLocalPortAsync(
    localPort: 5432, remoteHost: "db.internal", remotePort: 5432);

// Remote (-R): ask the server to listen and forward back to a local target. Port 0 lets the server choose.
await using RemotePortForwarder remote = await client.ForwardRemotePortAsync(
    remotePort: 0, localHost: "127.0.0.1", localPort: 8080);
Console.WriteLine($"server is listening on port {remote.BoundPort}");

// Dynamic (-D): a local SOCKS5 proxy that opens a tunnel per request.
await using DynamicPortForwarder dynamic = await client.ForwardDynamicPortAsync(localPort: 1080);
```

Dispose a forwarder to stop it (a remote forwarder also sends `cancel-tcpip-forward`).

## Running a server

```csharp
using System.Net;
using Bam.Ssh.Authentication;
using Bam.Ssh.Server;
using Bam.Ssh.Sftp;

await using SshServer server = new SshServer();

// A host key. Any Phase-5 private key doubles as a host-key signer; load one or generate from a seed.
server.AddHostKey(SshPrivateKeyReader.Read(await File.ReadAllTextAsync("/etc/ssh/host_ed25519")));

// Authentication policies.
server.UsePasswordAuthentication(new DelegatePasswordAuthenticator());     // your ISshPasswordAuthenticator
server.UsePublicKeyAuthentication(new DelegatePublicKeyAuthenticator());   // your ISshPublicKeyAuthenticator

// Command handlers. The context exposes ReadAsync (stdin), WriteAsync (stdout),
// WriteErrorAsync (stderr), and ExitAsync.
server.MapExec(async (context, cancellationToken) =>
{
    await context.WriteAsync($"you ran: {context.CommandLine}\n", cancellationToken);
    await context.ExitAsync(0, cancellationToken);
});
server.MapShell(async (context, cancellationToken) => { /* run a shell */ });

// Subsystems and features.
server.MapSftp(new PhysicalSftpFileSystem("/srv/sftp"));   // path-jailed virtual filesystem
server.MapScp(new PhysicalSftpFileSystem("/srv/sftp"));    // SCP over exec, same store
server.EnableTcpForwarding();                              // honor the peer's -L / -R / -D

await server.StartAsync(new IPEndPoint(IPAddress.Any, 2222));
Console.WriteLine($"listening on {server.ListenEndPoint}");
```

The two authentication interfaces are tiny — implement `ISshPasswordAuthenticator.AuthenticateAsync(user,
password, ct)` and `ISshPublicKeyAuthenticator` against your own credential store. For embedding (custom
transports, tests), `AcceptAsync(ISshDuplexStream)` serves one already-established connection instead of
binding a TCP listener.

## Next steps

- The [documentation hub](../README.md) links every per-layer protocol walkthrough in reading order.
- The [decision log](../decisions.md) explains the *why* behind the design.
- Security defaults: modern ciphers only, host-key trust enforced before auth, publickey signatures verified
  against the session-id-bound blob, and the physical SFTP filesystem is jailed to its root.
