using System.Buffers;
using System.Buffers.Binary;
using Bam.Ssh.Transport;
using Bam.Test;

namespace Bam.Ssh.Tests.Unit;

/// <summary>
/// Verifies the Phase 4 packet ciphers (chacha20-poly1305, aes-gcm, aes-ctr+hmac) and the cipher
/// factory: correct framing geometry, multi-packet round-trip through the real framing (proving
/// nonce/counter/sequence advancement stays in sync), separately-decryptable length, and rejection
/// of tampered ciphertext or MAC bytes.
/// </summary>
[UnitTestMenu("SshPacketCiphersShould", Selector = "cph")]
public class SshPacketCiphersShould : UnitTestMenuContainer
{
    private static readonly byte[][] Payloads = new byte[][]
    {
        new byte[] { 0x14 },
        MakePayload(0x15, 20),
        MakePayload(0x50, 200),
        MakePayload(0x21, 7),
    };

    [UnitTest]
    public void RoundTripChaCha20Poly1305()
    {
        AssertRoundTrips(SshAlgorithmNames.ChaCha20Poly1305, SshAlgorithmNames.HmacSha2256);
    }

    [UnitTest]
    public void RoundTripAes256Gcm()
    {
        AssertRoundTrips(SshAlgorithmNames.Aes256Gcm, SshAlgorithmNames.HmacSha2256);
    }

    [UnitTest]
    public void RoundTripAes128Gcm()
    {
        AssertRoundTrips(SshAlgorithmNames.Aes128Gcm, SshAlgorithmNames.HmacSha2256);
    }

    [UnitTest]
    public void RoundTripAes256CtrHmacSha256()
    {
        AssertRoundTrips(SshAlgorithmNames.Aes256Ctr, SshAlgorithmNames.HmacSha2256);
    }

    [UnitTest]
    public void RoundTripAes256CtrHmacSha512()
    {
        AssertRoundTrips(SshAlgorithmNames.Aes256Ctr, SshAlgorithmNames.HmacSha2512);
    }

    [UnitTest]
    public void RoundTripAes128Ctr()
    {
        AssertRoundTrips(SshAlgorithmNames.Aes128Ctr, SshAlgorithmNames.HmacSha2256);
    }

    [UnitTest]
    public void RejectTamperedPackets()
    {
        When.A<object>("rejects a packet whose trailing MAC/tag byte was flipped, for every cipher",
            new object(),
            (ignored) =>
            {
                (string Cipher, string Mac)[] suites = new (string, string)[]
                {
                    (SshAlgorithmNames.ChaCha20Poly1305, SshAlgorithmNames.HmacSha2256),
                    (SshAlgorithmNames.Aes256Gcm, SshAlgorithmNames.HmacSha2256),
                    (SshAlgorithmNames.Aes128Gcm, SshAlgorithmNames.HmacSha2256),
                    (SshAlgorithmNames.Aes256Ctr, SshAlgorithmNames.HmacSha2256),
                    (SshAlgorithmNames.Aes256Ctr, SshAlgorithmNames.HmacSha2512),
                    (SshAlgorithmNames.Aes128Ctr, SshAlgorithmNames.HmacSha2256),
                };
                bool[] rejected = new bool[suites.Length * 2];
                for (int i = 0; i < suites.Length; i++)
                {
                    rejected[i * 2] = DetectsTamper(suites[i].Cipher, suites[i].Mac, macByte: true);
                    rejected[i * 2 + 1] = DetectsTamper(suites[i].Cipher, suites[i].Mac, macByte: false);
                }
                return rejected;
            })
        .TheTest
        .ShouldPass(because =>
        {
            bool[] rejected = (bool[])because.Result;
            foreach (bool r in rejected)
            {
                because.ItsTrue("a tampered packet fails authentication", r);
            }
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void ExposeCorrectGeometryPerCipher()
    {
        When.A<object>("reports the RFC-mandated geometry, MAC length, and length-peek size",
            new object(),
            (ignored) =>
            {
                ISshPacketCipher chacha = Make(SshAlgorithmNames.ChaCha20Poly1305, SshAlgorithmNames.HmacSha2256);
                ISshPacketCipher gcm = Make(SshAlgorithmNames.Aes256Gcm, SshAlgorithmNames.HmacSha2256);
                ISshPacketCipher ctr256 = Make(SshAlgorithmNames.Aes256Ctr, SshAlgorithmNames.HmacSha2256);
                ISshPacketCipher ctr512 = Make(SshAlgorithmNames.Aes256Ctr, SshAlgorithmNames.HmacSha2512);

                bool[] results = new bool[10];
                results[0] = chacha.Geometry.BlockSize == 8 && !chacha.Geometry.LengthIsEncrypted;
                results[1] = chacha.MacLength == 16 && chacha.LengthPeekSize == 4;
                results[2] = gcm.Geometry.BlockSize == 16 && !gcm.Geometry.LengthIsEncrypted;
                results[3] = gcm.MacLength == 16 && gcm.LengthPeekSize == 4;
                results[4] = ctr256.Geometry.BlockSize == 16 && ctr256.Geometry.LengthIsEncrypted;
                results[5] = ctr256.MacLength == 32 && ctr256.LengthPeekSize == 16;
                results[6] = ctr512.MacLength == 64 && ctr512.LengthPeekSize == 16;
                results[7] = Make(SshAlgorithmNames.Aes128Gcm, SshAlgorithmNames.HmacSha2256).MacLength == 16;
                results[8] = Make(SshAlgorithmNames.Aes128Ctr, SshAlgorithmNames.HmacSha2256).Geometry.BlockSize == 16;
                results[9] = Make(SshAlgorithmNames.Aes128Ctr, SshAlgorithmNames.HmacSha2256).MacLength == 32;
                return results;
            })
        .TheTest
        .ShouldPass(because =>
        {
            bool[] results = (bool[])because.Result;
            because.ItsTrue("chacha20-poly1305 aligns to 8 with a cleartext-length peek", results[0]);
            because.ItsTrue("chacha20-poly1305 has a 16-byte tag and 4-byte peek", results[1]);
            because.ItsTrue("aes-gcm aligns to 16 with the length excluded", results[2]);
            because.ItsTrue("aes-gcm has a 16-byte tag and 4-byte peek", results[3]);
            because.ItsTrue("aes-ctr aligns to 16 with the length encrypted", results[4]);
            because.ItsTrue("aes-ctr+hmac-sha2-256 has a 32-byte MAC and a full-block peek", results[5]);
            because.ItsTrue("aes-ctr+hmac-sha2-512 has a 64-byte MAC", results[6]);
            because.ItsTrue("aes128-gcm has a 16-byte tag", results[7]);
            because.ItsTrue("aes128-ctr aligns to 16", results[8]);
            because.ItsTrue("aes128-ctr+hmac-sha2-256 has a 32-byte MAC", results[9]);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RejectUnknownAlgorithmNames()
    {
        When.A<object>("throws for an unknown cipher name and an unknown MAC on a CTR cipher",
            new object(),
            (ignored) =>
            {
                bool unknownCipher = Throws(() => Make("aes256-cbc", SshAlgorithmNames.HmacSha2256));
                bool unknownMac = Throws(() => Make(SshAlgorithmNames.Aes256Ctr, "hmac-md5"));
                return new bool[] { unknownCipher, unknownMac };
            })
        .TheTest
        .ShouldPass(because =>
        {
            bool[] results = (bool[])because.Result;
            because.ItsTrue("an unknown cipher name throws", results[0]);
            because.ItsTrue("an unknown MAC for a CTR cipher throws", results[1]);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    private void AssertRoundTrips(string cipher, string mac)
    {
        When.A<object>($"round-trips {Payloads.Length} sequential packets through {cipher}/{mac}",
            new object(),
            (ignored) => RoundTrips(cipher, mac))
        .TheTest
        .ShouldPass(because =>
        {
            because.ItsTrue("every packet decrypts back to its exact framed bytes and the length peek matches", (bool)because.Result);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    private static bool RoundTrips(string cipher, string mac)
    {
        ISshPacketCipher encryptSide = Make(cipher, mac);
        ISshPacketCipher decryptSide = Make(cipher, mac);
        SshPacketEncoder encoder = new SshPacketEncoder(new FakeSshRandom(0x5A));

        uint sequence = 0;
        Span<byte> decryptedLength = stackalloc byte[4];
        foreach (byte[] payload in Payloads)
        {
            ArrayBufferWriter<byte> framed = new ArrayBufferWriter<byte>();
            encoder.Encode(payload, framed, encryptSide.Geometry);
            byte[] framedBytes = framed.WrittenSpan.ToArray();

            ArrayBufferWriter<byte> wire = new ArrayBufferWriter<byte>();
            encryptSide.TransformOutgoing(framedBytes, sequence, wire);
            byte[] wireBytes = wire.WrittenSpan.ToArray();

            uint peekedLength = decryptSide.DecryptLength(wireBytes.AsSpan(0, decryptSide.LengthPeekSize), sequence, decryptedLength);
            if (peekedLength != BinaryPrimitives.ReadUInt32BigEndian(framedBytes))
            {
                return false;
            }

            ArrayBufferWriter<byte> recovered = new ArrayBufferWriter<byte>();
            if (!decryptSide.VerifyAndDecrypt(wireBytes, sequence, recovered))
            {
                return false;
            }
            if (!recovered.WrittenSpan.SequenceEqual(framedBytes))
            {
                return false;
            }
            sequence++;
        }
        return true;
    }

    private static bool DetectsTamper(string cipher, string mac, bool macByte)
    {
        ISshPacketCipher encryptSide = Make(cipher, mac);
        ISshPacketCipher decryptSide = Make(cipher, mac);
        SshPacketEncoder encoder = new SshPacketEncoder(new FakeSshRandom(0x5A));

        byte[] payload = MakePayload(0x30, 40);
        ArrayBufferWriter<byte> framed = new ArrayBufferWriter<byte>();
        encoder.Encode(payload, framed, encryptSide.Geometry);
        byte[] framedBytes = framed.WrittenSpan.ToArray();

        ArrayBufferWriter<byte> wire = new ArrayBufferWriter<byte>();
        encryptSide.TransformOutgoing(framedBytes, 0, wire);
        byte[] wireBytes = wire.WrittenSpan.ToArray();

        // macByte: flip the last (MAC/tag) byte; otherwise flip a mid-packet ciphertext byte.
        int flipIndex = macByte ? wireBytes.Length - 1 : wireBytes.Length - decryptSide.MacLength - 1;
        wireBytes[flipIndex] ^= 0xFF;

        Span<byte> decryptedLength = stackalloc byte[4];
        decryptSide.DecryptLength(wireBytes.AsSpan(0, decryptSide.LengthPeekSize), 0, decryptedLength);
        ArrayBufferWriter<byte> recovered = new ArrayBufferWriter<byte>();
        return !decryptSide.VerifyAndDecrypt(wireBytes, 0, recovered);
    }

    private static ISshPacketCipher Make(string cipher, string mac)
    {
        return SshCipherFactory.Create(cipher, mac, Pattern(1), Pattern(65), Pattern(129));
    }

    private static byte[] Pattern(byte seed)
    {
        byte[] bytes = new byte[64];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = (byte)(seed + i);
        }
        return bytes;
    }

    private static byte[] MakePayload(byte messageNumber, int length)
    {
        byte[] payload = new byte[length];
        payload[0] = messageNumber;
        for (int i = 1; i < length; i++)
        {
            payload[i] = (byte)(i * 7 + messageNumber);
        }
        return payload;
    }

    private static bool Throws(Action action)
    {
        try
        {
            action();
            return false;
        }
        catch (SshKeyExchangeException)
        {
            return true;
        }
    }
}
