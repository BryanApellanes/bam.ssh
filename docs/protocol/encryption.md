# Encryption & MAC Walkthrough (Phase 4)

How bam.ssh turns the key material from Phase 3 into live packet encryption and authentication, and
how it rekeys (RFC 4253 §6.3–§6.4, §7.2, §9; RFC 4344; RFC 5647; RFC 6668; OpenSSH
PROTOCOL.chacha20poly1305). Types live in `bam.ssh.transport` (namespace `Bam.Ssh.Transport`).
Rationale is in the Phase 4 design ([bam.ssh#7](https://github.com/BryanApellanes/bam.ssh/issues/7))
and decisions D-008/D-010/D-011.

## Where encryption plugs in

Encryption is the per-direction `ISshPacketCipher` seam the Phase 2 `SshPacketWriter`/`SshPacketReader`
apply around the Phase 1 framing (D-008). Before key exchange both directions use `NonePacketCipher`
(cleartext identity). When `SshClientKeyExchange` finishes the SSH_MSG_NEWKEYS exchange it builds the
two directional ciphers with `SshCipherFactory` and installs them with `SshTransport.ApplyKeys`, which
calls `SwapCipher` on the reader and writer. **Sequence numbers are not reset** at the swap
(RFC 4253 §6.4), so the first encrypted packet keeps counting from where the cleartext handshake left
off.

The cipher owns three framing facts the loop needs: `Geometry` (padding alignment + whether the length
is encrypted), `MacLength` (trailing bytes), and `LengthPeekSize` (how many leading bytes are needed to
learn the packet length). `DecryptLength` takes the sequence number because chacha20-poly1305 keys its
length cipher on it; the other modes ignore it.

## The three cipher families

| Cipher | Length field | Auth | Padding block | Crypto |
|---|---|---|---|---|
| `chacha20-poly1305@openssh.com` | encrypted with K_1, separately decryptable | Poly1305 tag (16) over encrypted length ‖ payload | 8, length excluded | **BouncyCastle** ChaCha20 + Poly1305 (D-011) |
| `aes256-gcm@openssh.com` / `aes128-gcm@openssh.com` | cleartext, authenticated as AAD | GCM tag (16) | 16, length excluded | BCL `AesGcm` |
| `aes256-ctr` / `aes128-ctr` (+ `hmac-sha2-256`/`512`) | encrypted (inside CTR stream) | HMAC (32/64) over seq ‖ cleartext | 16, length included | BCL `Aes` (ECB keystream) + `IncrementalHash` HMAC |

### chacha20-poly1305@openssh.com — `ChaCha20Poly1305Cipher`
Two ChaCha20 keys from the 64-byte encryption key: **K_2** (first 32 bytes) encrypts the payload,
**K_1** (last 32 bytes) encrypts the 4-byte length field. The nonce is the packet's 64-bit big-endian
sequence number. The Poly1305 one-time key is the first 32 bytes of the K_2 keystream (ChaCha block
counter 0); the payload is encrypted from block counter 1 (bam.ssh consumes a full 64-byte block-0
keystream to reach counter 1, discarding the unused 32 bytes — equivalent to OpenSSH's explicit counter
reset). The tag authenticates the encrypted length concatenated with the encrypted payload and is
verified (constant-time) **before** any plaintext is produced. The BCL `ChaCha20Poly1305` cannot
express this two-key/length-cipher construction, so BouncyCastle's raw `ChaChaEngine` + `Poly1305` are
used (D-011).

### aes-gcm — `AesGcmCipher`
The 4-byte length travels in the clear and is passed as additional authenticated data; the
padding_length, payload, and padding are encrypted and followed by the 16-byte tag. The 12-byte nonce
is seeded from the derived IV (4-byte fixed prefix + 8-byte invocation counter) and the counter is
incremented once per packet (RFC 5647 §7.1), so it never repeats for a key. `AesGcm.Decrypt` throws
`AuthenticationTagMismatchException` on a bad tag, which the cipher turns into a `false` return.

### aes-ctr + HMAC — `AesCtrCipher`
Classic encrypt-and-MAC (RFC 4253 §6.4): the MAC is computed over the sequence number concatenated
with the **cleartext** packet, and the whole packet — length included — is then encrypted in counter
mode. The 128-bit counter starts at the derived IV and increments per 16-byte block continuously across
the session (never reset per packet). AES-CTR is built from the BCL `Aes` ECB primitive because the BCL
exposes no CTR mode. `DecryptLength` decrypts only the first block to read the length and deliberately
does **not** advance the counter, so `VerifyAndDecrypt` re-derives the same keystream from block 0.
The recovered MAC is compared with `CryptographicOperations.FixedTimeEquals`.

## The factory

`SshCipherFactory.Create(cipherName, macName, key, iv, integrityKey)` maps a negotiated name to a
cipher. AEAD ciphers authenticate inline and ignore `macName`; the counter-mode ciphers pair with the
negotiated HMAC. Each key argument is a full 64-byte derived block; the factory slices the exact prefix
each algorithm needs (RFC 4253 §7.2 keys are a prefix relationship). Client key exchange builds the
outbound cipher from client-to-server material and the inbound cipher from server-to-client material;
the server mirrors this.

## Rekeying

`SshClientKeyExchange.RekeyAsync(sessionId)` re-runs the whole exchange on an established connection
(RFC 4253 §9) and swaps in fresh ciphers, **preserving the original session id** while binding the new
keys to the new exchange hash and shared secret (§7.2). Deciding *when* to rekey (byte/time thresholds)
and not interleaving application data with the rekey exchange are the connection layer's responsibility
(Phase 6/7) and are deferred; Phase 4 provides the mechanism.

## Test coverage

bam.test unit tests (`bam.ssh.tests/Unit`): per-cipher multi-packet round-trip through the real framing
(proving nonce/counter/sequence advancement stays in sync); geometry/MAC-length/length-peek assertions;
tamper detection (a flipped MAC/tag byte and a flipped ciphertext byte both fail authentication) for all
six suites; factory type selection and unknown-name rejection; a full handshake over
`LoopbackDuplexStream` that activates each cipher family and round-trips encrypted application packets
in both directions through the real `SshTransport`; and a mid-session rekey that keeps the session id,
rotates the keys, and keeps carrying application data. Real-OpenSSH interop is deferred until the
bam.ssh server exists (Phase 8) — this machine has an `ssh` client but no `sshd`.
