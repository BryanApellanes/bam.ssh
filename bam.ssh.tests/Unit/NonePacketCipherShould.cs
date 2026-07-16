using System.Buffers;
using Bam.Ssh.Transport;
using Bam.Test;

namespace Bam.Ssh.Tests.Unit;

[UnitTestMenu("NonePacketCipherShould", Selector = "npc")]
public class NonePacketCipherShould : UnitTestMenuContainer
{
    [UnitTest]
    public void BehaveAsIdentityWithNoMac()
    {
        When.A<NonePacketCipher>("passes bytes through unchanged and reports no MAC",
            NonePacketCipher.Instance,
            (cipher) =>
            {
                byte[] framed = new byte[] { 0x00, 0x00, 0x00, 0x0C, 0x06, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A };

                ArrayBufferWriter<byte> outgoing = new ArrayBufferWriter<byte>();
                cipher.TransformOutgoing(framed, 0, outgoing);
                bool outgoingIdentity = outgoing.WrittenSpan.SequenceEqual(framed);

                Span<byte> decryptedLength = stackalloc byte[4];
                uint length = cipher.DecryptLength(framed, 0, decryptedLength);
                bool lengthCorrect = length == 0x0C && decryptedLength.SequenceEqual(new byte[] { 0x00, 0x00, 0x00, 0x0C });

                ArrayBufferWriter<byte> incoming = new ArrayBufferWriter<byte>();
                bool verified = cipher.VerifyAndDecrypt(framed, 0, incoming);
                bool incomingIdentity = incoming.WrittenSpan.SequenceEqual(framed);

                bool geometryDefault = cipher.Geometry.BlockSize == 8 && cipher.MacLength == 0 && cipher.LengthPeekSize == 4;

                return new bool[] { outgoingIdentity, lengthCorrect, verified, incomingIdentity, geometryDefault };
            })
        .TheTest
        .ShouldPass(because =>
        {
            bool[] results = (bool[])because.Result;
            because.ItsTrue("outgoing transform is identity", results[0]);
            because.ItsTrue("length decrypts to the cleartext big-endian value", results[1]);
            because.ItsTrue("verify-and-decrypt succeeds", results[2]);
            because.ItsTrue("incoming transform is identity", results[3]);
            because.ItsTrue("geometry is an 8-byte block with no MAC", results[4]);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }
}
