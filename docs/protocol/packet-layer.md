# Packet Layer Walkthrough (Phase 1)

How bam.ssh represents SSH's lowest protocol layer: the RFC 4251 wire encoding and the
RFC 4253 §6 binary packet format. Everything here lives in `bam.ssh.common`, namespace `Bam.Ssh`.
The design rationale (alternatives, trade-offs) is in the Phase 1 design
([bam.ssh#1](https://github.com/BryanApellanes/bam.ssh/issues/1)).

## The binary packet format (RFC 4253 §6)

```
uint32    packet_length      ← byte count of everything after this field (excl. MAC)
byte      padding_length     ← 4..255
byte[n1]  payload            ← n1 = packet_length - padding_length - 1
byte[n2]  random padding     ← n2 = padding_length
byte[m]   mac                ← handled by the cipher layer (Phase 4); not framed here
```

Padding must bring the packet to a multiple of **max(8, cipher block size)**. *Which* bytes
count toward that multiple depends on the cipher mode, which is why the encoder is
parameterized by `SshPacketGeometry`:

| Mode | Aligned region | `LengthIsEncrypted` |
|---|---|---|
| Classic (aes*-ctr + MAC) | length field + padding_length + payload + padding | `true` |
| AEAD / encrypt-then-MAC (chacha20-poly1305, aes-gcm — Phase 4) | padding_length + payload + padding only | `false` |

`SshPacketEncoder.GetPaddingLength` computes the smallest padding ≥ 4 satisfying the alignment;
padding bytes come from an injected `ISshRandom` (production: `SecureSshRandom` over
`RandomNumberGenerator`).

## Decoding and hardening

`SshPacketDecoder.TryDecode(ref ReadOnlySequence<byte>, out SshPacketFrame)` is built for the
System.IO.Pipelines read loop: buffer what has arrived, try to decode, read more when told to wait.
Validation order matters — every declared length is checked **before** any commitment:

1. Fewer than 4 bytes buffered → `false` (wait).
2. Read `packet_length`; reject `< 5` or `> SshPacketLimits.MaxPacketLength` (default 262144,
   OpenSSH-compatible; the RFC must-accept floor of 35000 is enforced as the configurable minimum)
   → `SshPacketFormatException` carrying `SshDisconnectReason.ProtocolError`. Rejection happens
   *before* waiting for the body, so a hostile length can never force unbounded buffering.
3. Full frame not yet buffered → `false` (buffer growth is bounded by the already-validated length).
4. Reject `padding_length < 4` or `padding_length > packet_length - 1`.
5. Payload length computed by checked subtraction; the frame's payload is a zero-copy slice of the
   input, and the input sequence is advanced past the frame.

The payload slice references the caller's buffer: parse it (with `SshWireReader`) before advancing
the underlying `PipeReader`.

## Wire encoding (RFC 4251 §5)

`SshWireWriter` (over `IBufferWriter<byte>`) and `SshWireReader` (over `ReadOnlySpan<byte>`) are
stack-only ref structs — encoding and decoding allocate nothing beyond the destination buffer and
whatever the target type demands (only `string` materialization allocates). All integers are
big-endian. Types:

| SSH type | Write | Read | Notes |
|---|---|---|---|
| byte, boolean | `WriteByte`/`WriteBoolean` | `ReadByte`/`ReadBoolean` | read treats any non-zero as true, per RFC |
| uint32, uint64 | `WriteUInt32`/`WriteUInt64` | `ReadUInt32`/`ReadUInt64` | |
| string | `WriteString` (binary) / `WriteText` (UTF-8) | `ReadString` (span slice) / `ReadText` | length prefix validated against remaining bytes before slicing |
| mpint | `WriteMultiPrecisionInteger` (unsigned magnitude) / `WriteMultiPrecisionIntegerRaw` | `ReadMultiPrecisionInteger` (raw) / `ReadMultiPrecisionIntegerMagnitude` | see below |
| name-list | `WriteNameList` | `ReadNameList` | `SshNameList` validates at construction: printable ASCII, no empty names |

### mpint rules (`SshMpint`)

Two's complement, big-endian, **minimal length**: zero is the empty string; a positive value whose
high bit is set gains one `0x00` sign byte; unnecessary leading `0x00`/`0xFF` bytes are rejected on
read (`ValidateMinimalEncoding`). The protocol only transmits non-negative values, so the primary
API works in unsigned magnitudes (`ToUnsignedMagnitude` rejects negatives); the raw passthrough
exists for RFC-example fidelity and is covered by the RFC's own worked vectors
(`0`, `9a378f9b2e332a7`, `80`, `-1234`, `-deadbeef`) in the test suite.

## Sequence numbers

`SshSequenceNumber` (RFC 4253 §6.4): one per direction, starts at 0, `Advance()` returns the
number for the packet being processed and increments, wrapping mod 2³²; never reset by rekeying.
Owned by the transport (Phase 2) — deliberately *not* internal to encoder or decoder, because the
MAC computation (Phase 4) needs the number alongside cipher state.

## Sensitive buffers

`SshRentedBuffer` wraps `ArrayPool<byte>.Shared` and zeroes the used region with
`CryptographicOperations.ZeroMemory` on dispose, so key material staged in pooled arrays never
lingers after release.

## Test coverage

23 bam.test unit tests in `bam.ssh.tests/Unit` cover: RFC worked vectors for mpint and name-list,
round-trips for every primitive, truncation/overlong/non-minimal rejection per reader method,
padding alignment sweeps (payloads 0–1024 × block sizes 8/16, both geometry modes), deterministic
padding via a fake `ISshRandom`, byte-at-a-time and multi-segment reassembly, multi-frame buffers,
every decoder rejection branch (with disconnect-reason assertions), sequence wrap at 2³², and
buffer zeroing on dispose.
