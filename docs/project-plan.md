# bam.ssh Project Plan

Running implementation plan. Updated continuously as phases complete. Each phase must compile, include tests, and include documentation before the next phase begins. No phase is skipped.

## Phase status

| Phase | Scope | Status |
|---|---|---|
| 0 | Repo scaffold, bamtk submodule registration, epic + board wiring | **Complete** (bamtk PR [#22](https://github.com/BryanApellanes/bamtk/pull/22)) |
| 1 | Packet layer: binary encoding (RFC 4251), packet framing (RFC 4253 §6), sequence numbers, buffer pooling | **Complete** — 18 types in `bam.ssh.common`, 23 tests, walkthrough in [docs/protocol/packet-layer.md](protocol/packet-layer.md) |
| 2 | Transport: version exchange, banner, packet pipeline, disconnect/ignore/debug | **Complete** — `bam.ssh.transport` + diagnostics seam, 15 tests, walkthrough in [docs/protocol/transport-layer.md](protocol/transport-layer.md) |
| 3 | Key exchange: curve25519-sha256, ecdh-sha2-nistp256, dh-group14-sha256; KEXINIT negotiation; exchange hash; key derivation | Not started |
| 4 | Encryption: chacha20-poly1305@openssh.com, aes256-gcm@openssh.com, aes128-gcm@openssh.com, aes*-ctr + HMAC-SHA2; rekeying | Not started |
| 5 | Authentication: password, publickey (Ed25519/ECDSA/RSA-SHA2), keyboard-interactive; pluggable methods; key file formats | Not started |
| 6 | Channels: open/close, window flow control, exec/shell/subsystem, env, PTY, signals, exit status | Not started |
| 7 | Client: SshClient high-level API, known_hosts/TOFU host key verification, keep-alive | Not started |
| 8 | Server: SshServer high-level API, host keys, auth policies, handlers, limits/timeouts | Not started |
| 9 | SFTP: protocol v3 (OpenSSH-compatible), client + server, virtual filesystem | Not started |
| 10 | SCP: upload/download, recursive | Not started |
| 11 | Port forwarding: local, remote, dynamic SOCKS | Not started |
| 12 | Performance: benchmarks, allocation elimination, pipelines tuning | Not started |
| 13 | Documentation: architecture, protocol walkthrough, diagrams, API reference, guides | Not started |

## RFC map

| RFC | Title | Consumed by |
|---|---|---|
| 4250 | SSH Protocol Assigned Numbers | common |
| 4251 | SSH Protocol Architecture (data types, naming) | common |
| 4253 | SSH Transport Layer Protocol | common, transport |
| 5656 | Elliptic Curve Algorithm Integration | transport |
| 8731 | curve25519-sha256 Key Exchange | transport |
| 4344 | AES-CTR Transport Modes | transport |
| 5647 / openssh PROTOCOL | AES-GCM / chacha20-poly1305 | transport |
| 6668 | HMAC-SHA2 MACs | transport |
| 4252 | SSH Authentication Protocol | authentication |
| 8332 | RSA SHA-2 public key algorithms | authentication, transport |
| 8709 | Ed25519/Ed448 public key algorithms | authentication, transport |
| 5656 | ECDSA public key algorithms (`ecdsa-sha2-*`) | authentication, transport |
| 4254 | SSH Connection Protocol | connection |
| 4716 / OpenSSH key-v1 | Key file formats | authentication |
| draft-ietf-secsh-filexfer-02 (SFTP v3) | SFTP | sftp |

## Deferred / intentionally unsupported (running list)

Tracked with rationale in `docs/decisions.md` as encountered. Initial known deferrals:

- SSH1 protocol — obsolete, insecure, will not implement.
- Compression (`zlib`, `zlib@openssh.com`) — negotiated as `none` initially; hooks present, implementation deferred (see decisions log).
- GSS-API authentication (RFC 4462) — pluggable auth model leaves room; not in initial scope.
- X11 forwarding — architecture hooks only, per directive.
