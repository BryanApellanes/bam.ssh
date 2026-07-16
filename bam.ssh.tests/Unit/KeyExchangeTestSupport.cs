using System.Security.Cryptography;
using Bam.Ssh.Transport;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Bam.Ssh.Tests.Unit;

/// <summary>
/// Test-only host-key signers. Each generates a key pair, exposes the SSH K_S public blob, and signs
/// an exchange hash producing the SSH signature blob — the server side of what production only
/// verifies. Used to prove the verification path end to end.
/// </summary>
internal static class TestHostKeys
{
    public static (byte[] KeyBlob, Func<byte[], byte[]> Sign) CreateEd25519(byte fillSeed = 0x42)
    {
        byte[] seed = new byte[32];
        for (int i = 0; i < seed.Length; i++)
        {
            seed[i] = (byte)(fillSeed + i);
        }
        Ed25519PrivateKeyParameters privateKey = new Ed25519PrivateKeyParameters(seed, 0);
        byte[] publicKey = privateKey.GeneratePublicKey().GetEncoded();

        byte[] keyBlob = BuildBlob(writer =>
        {
            writer.WriteText(SshAlgorithmNames.SshEd25519);
            writer.WriteString(publicKey);
        });

        byte[] Sign(byte[] hash)
        {
            Ed25519Signer signer = new Ed25519Signer();
            signer.Init(forSigning: true, privateKey);
            signer.BlockUpdate(hash, 0, hash.Length);
            byte[] signature = signer.GenerateSignature();
            return BuildBlob(writer =>
            {
                writer.WriteText(SshAlgorithmNames.SshEd25519);
                writer.WriteString(signature);
            });
        }

        return (keyBlob, Sign);
    }

    public static (byte[] KeyBlob, Func<byte[], byte[]> Sign) CreateEcdsaNistP256()
    {
        ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ECParameters parameters = ecdsa.ExportParameters(includePrivateParameters: false);
        byte[] point = new byte[65];
        point[0] = 0x04;
        parameters.Q.X!.CopyTo(point, 1 + (32 - parameters.Q.X!.Length));
        parameters.Q.Y!.CopyTo(point, 33 + (32 - parameters.Q.Y!.Length));

        byte[] keyBlob = BuildBlob(writer =>
        {
            writer.WriteText(SshAlgorithmNames.EcdsaSha2Nistp256);
            writer.WriteText(SshAlgorithmNames.Nistp256CurveName);
            writer.WriteString(point);
        });

        byte[] Sign(byte[] hash)
        {
            byte[] ieee = ecdsa.SignData(hash, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            byte[] r = ieee.AsSpan(0, 32).ToArray();
            byte[] s = ieee.AsSpan(32, 32).ToArray();
            byte[] inner = BuildBlob(writer =>
            {
                writer.WriteMultiPrecisionInteger(r);
                writer.WriteMultiPrecisionInteger(s);
            });
            return BuildBlob(writer =>
            {
                writer.WriteText(SshAlgorithmNames.EcdsaSha2Nistp256);
                writer.WriteString(inner);
            });
        }

        return (keyBlob, Sign);
    }

    public static (byte[] KeyBlob, Func<byte[], byte[]> Sign) CreateRsa(string signatureName = SshAlgorithmNames.RsaSha2256)
    {
        RSA rsa = RSA.Create(2048);
        RSAParameters parameters = rsa.ExportParameters(includePrivateParameters: false);

        byte[] keyBlob = BuildBlob(writer =>
        {
            writer.WriteText(SshAlgorithmNames.SshRsaKeyType);
            writer.WriteMultiPrecisionInteger(parameters.Exponent!);
            writer.WriteMultiPrecisionInteger(parameters.Modulus!);
        });

        HashAlgorithmName hashName = signatureName == SshAlgorithmNames.RsaSha2512
            ? HashAlgorithmName.SHA512
            : HashAlgorithmName.SHA256;

        byte[] Sign(byte[] hash)
        {
            byte[] signature = rsa.SignData(hash, hashName, RSASignaturePadding.Pkcs1);
            return BuildBlob(writer =>
            {
                writer.WriteText(signatureName);
                writer.WriteString(signature);
            });
        }

        return (keyBlob, Sign);
    }

    private static byte[] BuildBlob(Action<SshWireWriter> write)
    {
        PooledBufferWriter buffer = new PooledBufferWriter(128);
        try
        {
            SshWireWriter writer = new SshWireWriter(buffer);
            write(writer);
            return buffer.WrittenSpan.ToArray();
        }
        finally
        {
            buffer.Dispose();
        }
    }
}

/// <summary>
/// A test-only server responder that plays the server role of key exchange over a loopback transport
/// using the production primitives plus a generated host key. Proves the client key exchange
/// interoperates end to end. Optionally corrupts its signature to exercise the rejection path.
/// </summary>
internal sealed class TestServerKeyExchange
{
    private readonly SshTransport _transport;
    private readonly byte[] _hostKeyBlob;
    private readonly Func<byte[], byte[]> _sign;
    private readonly bool _corruptSignature;

    public TestServerKeyExchange(SshTransport transport, byte[] hostKeyBlob, Func<byte[], byte[]> sign, bool corruptSignature = false)
    {
        _transport = transport;
        _hostKeyBlob = hostKeyBlob;
        _sign = sign;
        _corruptSignature = corruptSignature;
    }

    public SshSessionKeys? SessionKeys { get; private set; }

    public byte[]? ExchangeHash { get; private set; }

    public async Task RunAsync(CancellationToken cancellationToken = default)
    {
        SshVersionExchangeResult version = _transport.VersionExchange;

        byte[] clientKexInit = await ReceiveAsync(SshMessageNumber.KexInit, cancellationToken).ConfigureAwait(false);
        SshKexInit serverKexInitMessage = SshKexInit.CreateLocal(SshAlgorithmCatalog.Default, SecureSshRandom.Instance);
        byte[] serverKexInit = Serialize(serverKexInitMessage);
        await _transport.SendPacketAsync(serverKexInit, cancellationToken).ConfigureAwait(false);

        SshNegotiatedAlgorithms algorithms = SshAlgorithmNegotiation.Negotiate(
            SshKexInit.Parse(clientKexInit), SshKexInit.Parse(serverKexInit));
        ISshKeyExchangeAlgorithm algorithm = SshKeyExchangeAlgorithmFactory.Create(algorithms.KeyExchange);

        byte[] initPayload = await ReceiveAsync(SshMessageNumber.KexExchangeSpecific30, cancellationToken).ConfigureAwait(false);
        byte[] clientPublicValue = ReadPublicValue(initPayload, algorithm.PublicValueFormat);

        byte[] serverPublicValue = algorithm.CreateClientPublicValue();
        byte[] sharedSecret = algorithm.DeriveSharedSecret(clientPublicValue);

        byte[] exchangeHash = SshExchangeHash.Compute(
            algorithm.HashAlgorithm,
            version.RemoteRawBytes,
            version.LocalRawBytes,
            clientKexInit,
            serverKexInit,
            _hostKeyBlob,
            clientPublicValue,
            serverPublicValue,
            algorithm.PublicValueFormat,
            sharedSecret);

        byte[] signature = _sign(exchangeHash);
        if (_corruptSignature)
        {
            signature[signature.Length - 1] ^= 0xFF;
        }

        byte[] reply = BuildReply(_hostKeyBlob, serverPublicValue, signature, algorithm.PublicValueFormat);
        await _transport.SendPacketAsync(reply, cancellationToken).ConfigureAwait(false);

        await ReceiveAsync(SshMessageNumber.NewKeys, cancellationToken).ConfigureAwait(false);
        await _transport.SendPacketAsync(new byte[] { (byte)SshMessageNumber.NewKeys }, cancellationToken).ConfigureAwait(false);

        ExchangeHash = exchangeHash;
        SessionKeys = new SshSessionKeys(
            exchangeHash,
            SshKeyDerivation.DeriveKey(algorithm.HashAlgorithm, sharedSecret, exchangeHash, SshKeyDerivation.InitialIvClientToServer, exchangeHash, 64),
            SshKeyDerivation.DeriveKey(algorithm.HashAlgorithm, sharedSecret, exchangeHash, SshKeyDerivation.InitialIvServerToClient, exchangeHash, 64),
            SshKeyDerivation.DeriveKey(algorithm.HashAlgorithm, sharedSecret, exchangeHash, SshKeyDerivation.EncryptionKeyClientToServer, exchangeHash, 64),
            SshKeyDerivation.DeriveKey(algorithm.HashAlgorithm, sharedSecret, exchangeHash, SshKeyDerivation.EncryptionKeyServerToClient, exchangeHash, 64),
            SshKeyDerivation.DeriveKey(algorithm.HashAlgorithm, sharedSecret, exchangeHash, SshKeyDerivation.IntegrityKeyClientToServer, exchangeHash, 64),
            SshKeyDerivation.DeriveKey(algorithm.HashAlgorithm, sharedSecret, exchangeHash, SshKeyDerivation.IntegrityKeyServerToClient, exchangeHash, 64));
    }

    private async Task<byte[]> ReceiveAsync(SshMessageNumber expected, CancellationToken cancellationToken)
    {
        using SshIncomingPacket packet = await _transport.ReceivePacketAsync(cancellationToken).ConfigureAwait(false);
        if (packet.IsEmpty || packet.MessageNumber != (byte)expected)
        {
            throw new InvalidOperationException($"Server expected {(byte)expected} but got {(packet.IsEmpty ? 0 : packet.MessageNumber)}.");
        }
        return packet.Payload.ToArray();
    }

    private static byte[] Serialize(SshKexInit kexInit)
    {
        PooledBufferWriter buffer = new PooledBufferWriter(256);
        try
        {
            kexInit.WritePayload(buffer);
            return buffer.WrittenSpan.ToArray();
        }
        finally
        {
            buffer.Dispose();
        }
    }

    private static byte[] ReadPublicValue(byte[] payload, SshKeyExchangePublicValueFormat format)
    {
        SshWireReader reader = new SshWireReader(payload);
        reader.ReadByte();
        return format == SshKeyExchangePublicValueFormat.MultiPrecisionInteger
            ? reader.ReadMultiPrecisionIntegerMagnitude().ToArray()
            : reader.ReadString().ToArray();
    }

    private static byte[] BuildReply(byte[] hostKeyBlob, byte[] serverPublicValue, byte[] signature, SshKeyExchangePublicValueFormat format)
    {
        PooledBufferWriter buffer = new PooledBufferWriter(256);
        try
        {
            SshWireWriter writer = new SshWireWriter(buffer);
            writer.WriteByte((byte)SshMessageNumber.KexExchangeSpecific31);
            writer.WriteString(hostKeyBlob);
            if (format == SshKeyExchangePublicValueFormat.MultiPrecisionInteger)
            {
                writer.WriteMultiPrecisionInteger(serverPublicValue);
            }
            else
            {
                writer.WriteString(serverPublicValue);
            }
            writer.WriteString(signature);
            return buffer.WrittenSpan.ToArray();
        }
        finally
        {
            buffer.Dispose();
        }
    }
}
