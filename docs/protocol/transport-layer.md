# Transport Layer Walkthrough (Phase 2)

How bam.ssh turns a raw byte connection into an SSH binary-packet channel: identification exchange
(RFC 4253 §4.2) and a cleartext packet send/receive pipeline over the Phase 1 codecs, with the
encryption seam left open for Phases 3–4. Types live in `bam.ssh.transport`, namespace
`Bam.Ssh.Transport`; the diagnostics seam lives in `bam.ssh.common` (`Bam.Ssh`). Rationale is in the
Phase 2 design ([bam.ssh#3](https://github.com/BryanApellanes/bam.ssh/issues/3)).

## Layer shape

```
SshTransport            façade: connect, send, receive, disconnect, ApplyKeys
  ├─ SshVersionExchange     RFC 4253 §4.2 identification exchange
  ├─ SshPacketWriter        encode + cipher + send-sequence, per direction
  ├─ SshPacketReader        read + cipher + de-frame + recv-sequence, per direction
  └─ ISshDuplexStream       byte transport (SshTcpDuplexStream today; Unix/custom additive)
        ISshPacketCipher    encryption/MAC seam (NonePacketCipher until Phase 4)
```

## Identification exchange (RFC 4253 §4.2)

`SshIdentificationString` parses/formats the `SSH-protoversion-softwareversion[ comments]` line.
`SshVersionExchange.ExchangeAsync` writes the local `SSH-2.0-...` line, then reads peer lines,
**tolerating banner lines** (any line not starting with `SSH-`) up to `MaxBannerLines`, until the
peer's identification arrives. Hardening (D-005): each line is bounded by
`MaxIdentificationLineLength` (255) and the banner count by `MaxBannerLines` (1024); both CRLF and
bare-LF endings are accepted; violations throw `SshTransportException` with a disconnect reason.
The result keeps both identification lines' **raw bytes without CRLF** — Phase 3 feeds them
verbatim into the key-exchange hash H.

## Packet pipeline

`SshPacketWriter.WriteAsync(payload)`:
1. Advance the send `SshSequenceNumber`.
2. Encode the payload into a framed packet (Phase 1 `SshPacketEncoder`) using the cipher's `Geometry`.
3. `ISshPacketCipher.TransformOutgoing` encrypts + appends MAC (identity for none) into the pipe.
4. Flush.

`SshPacketReader.ReadAsync()`:
1. Buffer `LengthPeekSize` bytes; `ISshPacketCipher.DecryptLength` yields `packet_length` (decrypting
   the length word for modes that encrypt it — cleartext read for none). Validate against limits
   **once**, before buffering the rest.
2. Buffer the whole wire packet (`4 + packet_length + MacLength`).
3. `VerifyAndDecrypt` authenticates + decrypts into a pooled cleartext buffer (MAC failure →
   `SshTransportException` with `MacError`).
4. Re-run the Phase 1 `SshPacketDecoder` on the cleartext to slice the payload, copy it into an owned
   `SshIncomingPacket` (pooled `SshRentedBuffer`), advance the recv sequence number, and advance the pipe.

`SshIncomingPacket` exposes `MessageNumber` (first byte), `Payload`, and `Body` (after the message
number); dispose it after parsing to return the pooled buffer.

## The cipher seam (D-008)

`ISshPacketCipher` is per-direction and holds that direction's cipher/MAC state. It exposes
`Geometry`, `MacLength`, `LengthPeekSize`, `TransformOutgoing`, `DecryptLength`, and `VerifyAndDecrypt`
— shaped to cover the three Phase 4 modes without changing the reader/writer:

| Mode | Length | MAC | Geometry |
|---|---|---|---|
| none (Phase 2) | cleartext | 0 | block 8, length in alignment |
| chacha20-poly1305@openssh.com | encrypted (separate key) | 16 (Poly1305) | block 8, length excluded |
| aes*-gcm@openssh.com | cleartext | 16 (GCM tag) | block 16, length excluded |
| aes*-ctr + hmac | cleartext | 32/64 (HMAC) | block 16, length in alignment |

`SshTransport.ApplyKeys(inbound, outbound)` swaps both directions at SSH_MSG_NEWKEYS; sequence
numbers continue unbroken (RFC 4253 §6.4).

## Transport-generic messages

`SshTransport.ReceivePacketAsync` handles them so upper layers never see them: SSH_MSG_IGNORE is
discarded, SSH_MSG_DEBUG is logged (via `ISshLogger`) and discarded, SSH_MSG_DISCONNECT throws
`SshDisconnectException` (carrying reason + description); everything else is returned. `SendDisconnectAsync`
builds and sends SSH_MSG_DISCONNECT then closes the transport.

## Diagnostics

`ISshLogger` (+ `NullSshLogger`) is a framework-free logging seam every layer can use without a
logging dependency (preserves AOT). `SshActivitySource` holds the `Bam.Ssh` `ActivitySource` for
OpenTelemetry-compatible spans; spans cost nothing when no listener is attached (D-007).

## Transports

`ISshDuplexStream` abstracts the byte channel as a `PipeReader`/`PipeWriter` pair. `SshTcpDuplexStream`
wraps a connected socket (Nagle disabled); Unix-socket and custom transports are additive
implementations. Tests use an in-memory `LoopbackDuplexStream` (two cross-wired pipes).

## Test coverage

15 bam.test unit tests (`bam.ssh.tests/Unit`) added this phase: identification parse/format and
rejection; loopback version exchange with banner tolerance, banner-cap and unsupported-version
rejection, and raw-byte capture; none-cipher identity behavior; writer/reader round-trips (payloads
0–4096, lockstep sequence numbers, multi-packet streaming, message-number/body split); and full
`SshTransport` loopback (connect, IGNORE/DEBUG handling, DISCONNECT, cipher swap via ApplyKeys).
A real-OpenSSH interop check is deferred to Phase 3 (a cleartext transport cannot complete a real
handshake — kex must follow version exchange immediately).
