using System.Security.Cryptography;
using Bam.Ssh.Transport;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;

namespace Bam.Ssh.Tests.Unit;

/// <summary>
/// Generates private-key material and serializes it to the on-disk formats the reader must parse:
/// unencrypted OpenSSH v1 (built here as the inverse of <c>OpenSshPrivateKeyParser</c>) for all three
/// key types, PKCS#8 PEM (BCL for RSA/ECDSA, BouncyCastle for Ed25519), plus an encrypted OpenSSH
/// header to exercise the deferred-encryption rejection path.
/// </summary>
internal static class PrivateKeyTestSupport
{
    private const uint CheckInt = 0x0A0B0C0D;

    public static byte[] Ed25519Seed()
    {
        byte[] seed = new byte[32];
        for (int i = 0; i < seed.Length; i++)
        {
            seed[i] = (byte)(0x11 + i);
        }
        return seed;
    }

    public static string OpenSshEd25519()
    {
        byte[] seed = Ed25519Seed();
        Ed25519PrivateKeyParameters priv = new Ed25519PrivateKeyParameters(seed, 0);
        byte[] publicKey = priv.GeneratePublicKey().GetEncoded();
        byte[] privateHalf = new byte[64];
        seed.CopyTo(privateHalf, 0);
        publicKey.CopyTo(privateHalf, 32);

        byte[] publicBlob = Build(writer =>
        {
            writer.WriteText(SshAlgorithmNames.SshEd25519);
            writer.WriteString(publicKey);
        });

        return BuildOpenSshPem(publicBlob, writer =>
        {
            writer.WriteText(SshAlgorithmNames.SshEd25519);
            writer.WriteString(publicKey);
            writer.WriteString(privateHalf);
        });
    }

    public static string OpenSshEcdsa()
    {
        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ECParameters parameters = ecdsa.ExportParameters(includePrivateParameters: true);
        byte[] point = BuildPoint(parameters);
        byte[] d = parameters.D!;

        byte[] publicBlob = Build(writer =>
        {
            writer.WriteText(SshAlgorithmNames.EcdsaSha2Nistp256);
            writer.WriteText(SshAlgorithmNames.Nistp256CurveName);
            writer.WriteString(point);
        });

        return BuildOpenSshPem(publicBlob, writer =>
        {
            writer.WriteText(SshAlgorithmNames.EcdsaSha2Nistp256);
            writer.WriteText(SshAlgorithmNames.Nistp256CurveName);
            writer.WriteString(point);
            writer.WriteMultiPrecisionInteger(d);
        });
    }

    public static string OpenSshRsa()
    {
        using RSA rsa = RSA.Create(2048);
        RSAParameters parameters = rsa.ExportParameters(includePrivateParameters: true);

        byte[] publicBlob = Build(writer =>
        {
            writer.WriteText(SshAlgorithmNames.SshRsaKeyType);
            writer.WriteMultiPrecisionInteger(parameters.Exponent!);
            writer.WriteMultiPrecisionInteger(parameters.Modulus!);
        });

        return BuildOpenSshPem(publicBlob, writer =>
        {
            writer.WriteText(SshAlgorithmNames.SshRsaKeyType);
            writer.WriteMultiPrecisionInteger(parameters.Modulus!);
            writer.WriteMultiPrecisionInteger(parameters.Exponent!);
            writer.WriteMultiPrecisionInteger(parameters.D!);
            writer.WriteMultiPrecisionInteger(parameters.InverseQ!);
            writer.WriteMultiPrecisionInteger(parameters.P!);
            writer.WriteMultiPrecisionInteger(parameters.Q!);
        });
    }

    public static string Pkcs8Ed25519()
    {
        Ed25519PrivateKeyParameters priv = new Ed25519PrivateKeyParameters(Ed25519Seed(), 0);
        using StringWriter stringWriter = new StringWriter();
        PemWriter pemWriter = new PemWriter(stringWriter);
        pemWriter.WriteObject(priv);
        pemWriter.Writer.Flush();
        return stringWriter.ToString();
    }

    public static string Pkcs8Rsa()
    {
        using RSA rsa = RSA.Create(2048);
        return rsa.ExportPkcs8PrivateKeyPem();
    }

    public static string Pkcs8Ecdsa()
    {
        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return ecdsa.ExportPkcs8PrivateKeyPem();
    }

    public static string EncryptedOpenSshEd25519()
    {
        // Only the header through kdfoptions matters; the parser rejects at the cipher check.
        byte[] body = Build(writer =>
        {
            writer.WriteRaw(System.Text.Encoding.ASCII.GetBytes("openssh-key-v1"));
            writer.WriteByte(0);
            writer.WriteText("aes256-ctr");
            writer.WriteText("bcrypt");
            writer.WriteString(new byte[] { 1, 2, 3, 4 });
            writer.WriteUInt32(1);
            writer.WriteString(new byte[] { 0 });
            writer.WriteString(new byte[] { 0 });
        });
        return WrapPem("OPENSSH PRIVATE KEY", body);
    }

    private static byte[] BuildPoint(ECParameters parameters)
    {
        byte[] point = new byte[65];
        point[0] = 0x04;
        byte[] x = parameters.Q.X!;
        byte[] y = parameters.Q.Y!;
        x.CopyTo(point, 1 + (32 - x.Length));
        y.CopyTo(point, 33 + (32 - y.Length));
        return point;
    }

    private static string BuildOpenSshPem(byte[] publicBlob, Action<SshWireWriter> writePrivateFields)
    {
        PooledBufferWriter privateBuffer = new PooledBufferWriter(512);
        try
        {
            SshWireWriter privateWriter = new SshWireWriter(privateBuffer);
            privateWriter.WriteUInt32(CheckInt);
            privateWriter.WriteUInt32(CheckInt);
            writePrivateFields(privateWriter);
            privateWriter.WriteText("bam-ssh-test");
            int padding = (8 - (privateBuffer.WrittenCount % 8)) % 8;
            for (int i = 1; i <= padding; i++)
            {
                privateWriter.WriteByte((byte)i);
            }
            byte[] privateSection = privateBuffer.WrittenSpan.ToArray();

            byte[] body = Build(writer =>
            {
                writer.WriteRaw(System.Text.Encoding.ASCII.GetBytes("openssh-key-v1"));
                writer.WriteByte(0);
                writer.WriteText("none");
                writer.WriteText("none");
                writer.WriteString(ReadOnlySpan<byte>.Empty);
                writer.WriteUInt32(1);
                writer.WriteString(publicBlob);
                writer.WriteString(privateSection);
            });
            return WrapPem("OPENSSH PRIVATE KEY", body);
        }
        finally
        {
            privateBuffer.Dispose();
        }
    }

    private static string WrapPem(string label, byte[] body)
    {
        string base64 = Convert.ToBase64String(body);
        System.Text.StringBuilder builder = new System.Text.StringBuilder();
        builder.Append("-----BEGIN ").Append(label).Append("-----\n");
        for (int i = 0; i < base64.Length; i += 70)
        {
            builder.Append(base64, i, Math.Min(70, base64.Length - i)).Append('\n');
        }
        builder.Append("-----END ").Append(label).Append("-----\n");
        return builder.ToString();
    }

    private static byte[] Build(Action<SshWireWriter> write)
    {
        PooledBufferWriter buffer = new PooledBufferWriter(256);
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
