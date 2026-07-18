# Performance (Phase 12)

Phase 12 adds a benchmark harness, measures the hot paths, and eliminates the avoidable per-packet
allocations it surfaced. The headline result: the two software ciphers that allocated buffers **proportional to
payload size** on every packet now allocate a small **constant** amount, and the counter-mode cipher is ~11×
faster.

## The harness (`bam.ssh.benchmarks`)

A minimal, dependency-free harness — **no BenchmarkDotNet** — matching the stack's zero-dependency,
reflection-free, Native-AOT ethos. `BenchmarkRunner` runs a warmup, forces a clean GC baseline, then times a
fixed iteration count while measuring managed allocation with `GC.GetTotalAllocatedBytes(precise: true)` (which
captures allocations on async continuation threads too). `BenchmarkResult` derives MiB/s, ns/op, and
bytes/op. Run it in Release:

```
dotnet run --project bam.ssh.benchmarks -c Release            # all scenarios
dotnet run --project bam.ssh.benchmarks -c Release -- packet  # packet layer only
dotnet run --project bam.ssh.benchmarks -c Release -- channel # end-to-end only
```

Two scenarios:
- **Packet layer** — frames a payload and round-trips it through an in-process pipe (`SshPacketWriter` →
  `SshPacketReader`) for the identity cipher and each real cipher family, at 4 KiB and 32 KiB. Isolates framing
  and per-cipher cost.
- **Channel throughput** — pushes 128 MiB through a session channel over a real `SshClient`↔`SshServer` TCP
  loopback with the negotiated cipher. The realistic number, with framing, encryption, flow-control windows,
  and pipelines all in the path.

### A note on measurement discipline

Absolute throughput on a developer laptop drifts with thermal state and background load: across separate runs
the **unchanged** aes256-gcm control moved by 3–4×. So the throughput figures below come from a **back-to-back
same-session A/B** (the changed files stashed, measured, restored, measured), and aes256-gcm/none are reported
as an *unchanged control*. **Allocation** figures use `GC.GetTotalAllocatedBytes(precise: true)` and are exact
and reproducible run-to-run — they are the trustworthy headline.

## Allocations eliminated

Three allocation sources in the per-packet hot path were removed, all behavior-preserving (the Phase 4 cipher
round-trip and tampered-rejection tests, and the full 118-test suite, still pass):

1. **`ChaCha20Poly1305Cipher`** allocated a fresh `ChaChaEngine`, `Poly1305`, and `KeyParameter` per packet, and
   — worst — `data.ToArray()` copied the *entire ciphertext* into a new array for the Poly1305 update. Now the
   engines, the MAC, and the key parameters are constructed once and reused (the cipher serves one direction
   and is not thread-safe, so re-`Init` before each packet resets state safely), and Poly1305 consumes the data
   through its `ReadOnlySpan` `BlockUpdate`/`DoFinal` overloads — no copy.
2. **`AesCtrCipher`** called the one-shot `Aes.EncryptEcb` **once per 16-byte block** (2048 calls for a 32 KiB
   packet) and created a new `IncrementalHash` HMAC per packet. Now the keystream is generated a **batch of 64
   blocks per ECB call** (bit-for-bit identical — each ECB block is independent) and the HMAC is created once and
   reset per packet.
3. **`SshPacketWriter`** allocated a `PooledBufferWriter` wrapper per packet; it now reuses one (the writer is
   single-threaded — callers serialize), so the fast paths allocate essentially nothing.

Measured per-packet allocation (exact, reproducible):

| cipher, 32 KiB packet | before B/op | after B/op | reduction |
|---|---:|---:|---:|
| chacha20-poly1305 | 69,264 | 952 | **~73×** |
| aes256-ctr + hmac-sha2-256 | 361,365 | 5,928 | **~61×** |
| aes256-gcm *(control, untouched)* | 64 | 32 | 2× (writer) |
| none *(control)* | 64 | 32 | 2× (writer) |

The crucial change is that chacha and CTR allocation is now **independent of payload size** — before, a bulk
transfer produced garbage proportional to the bytes moved.

## Throughput (back-to-back A/B, same machine state)

| cipher, 32 KiB packet | before MiB/s | after MiB/s | change |
|---|---:|---:|---:|
| aes256-ctr + hmac-sha2-256 | 5.7 | 65.5 | **~11× faster** |
| chacha20-poly1305 | 52.8 | 61.1 | ~1.15× faster |
| aes256-gcm *(control, untouched)* | 546 | ~540 | unchanged (as expected) |
| none *(control)* | ~3390 | ~3550 | unchanged |

The CTR win is the batched ECB call (the per-block one-shot call was the dominant cost). ChaCha throughput is
bound by BouncyCastle's software ChaCha20 core (D-009: the BCL exposes no raw ChaCha20 for the OpenSSH two-key
construction), so removing allocation helps only modestly there — its value is the 73× allocation cut.

## Finding: the default cipher caps end-to-end throughput

End-to-end channel throughput is **~61 MiB/s** — matching chacha20-poly1305's packet-layer number, because the
default cipher preference (`SshAlgorithmCatalog`) lists **chacha20-poly1305 first**. On AES-NI hardware,
aes256-gcm (BCL, hardware-accelerated) runs the packet layer ~9× faster (~540 vs ~61 MiB/s).

This is left as a **documented trade-off, not a code change**: chacha20-poly1305-first is a deliberate,
widely-used secure default (it is OpenSSH's preference and is constant-time in software). The catalog already
takes explicit preference lists in its constructor, so a deployment on AES-NI hardware that wants maximum
throughput can construct a catalog with `aes256-gcm` first — no library change required. Changing the shipped
default is a security-policy decision outside a performance pass.

## Deferred / not pursued

- Pooling the per-send `OutboundItem`/`TaskCompletionSource` in `SshConnection` — the end-to-end path already
  allocates only ~8.6 MB per 128 MiB pushed (~0.0066×); the remaining pressure is not worth the concurrency
  risk of a custom value-task source here.
- A hand-vectorized ChaCha20 to beat BouncyCastle — large surface, high risk; the aes-gcm path is the fast
  option on this hardware.
- Real-OpenSSH interop performance comparison (deferred stack-wide).
