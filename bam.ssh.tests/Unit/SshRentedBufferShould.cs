using Bam.Test;

namespace Bam.Ssh.Tests.Unit;

[UnitTestMenu("SshRentedBufferShould", Selector = "srb")]
public class SshRentedBufferShould : UnitTestMenuContainer
{
    [UnitTest]
    public void ZeroContentsOnDispose()
    {
        When.A<object>("zeroes the used region when disposed so secrets do not linger in the pool",
            new object(),
            (ignored) =>
            {
                SshRentedBuffer buffer = SshRentedBuffer.Rent(64);
                buffer.Span.Fill(0xEE);
                Memory<byte> observed = buffer.Memory;
                bool filledBeforeDispose = observed.Span.IndexOfAnyExcept((byte)0xEE) < 0;
                buffer.Dispose();
                bool zeroedAfterDispose = observed.Span.IndexOfAnyExcept((byte)0x00) < 0;
                return new bool[] { filledBeforeDispose, zeroedAfterDispose };
            })
        .TheTest
        .ShouldPass(because =>
        {
            bool[] results = (bool[])because.Result;
            because.ItsTrue("the buffer held the written bytes before dispose", results[0]);
            because.ItsTrue("the used region reads all zeros after dispose", results[1]);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void ExposeExactlyTheRequestedLength()
    {
        When.A<object>("exposes exactly the requested length regardless of pool rounding",
            new object(),
            (ignored) =>
            {
                SshRentedBuffer buffer = SshRentedBuffer.Rent(100);
                bool spanLength = buffer.Span.Length == 100;
                bool memoryLength = buffer.Memory.Length == 100;
                bool lengthProperty = buffer.Length == 100;
                buffer.Dispose();
                return new bool[] { spanLength, memoryLength, lengthProperty };
            })
        .TheTest
        .ShouldPass(because =>
        {
            bool[] results = (bool[])because.Result;
            because.ItsTrue("Span exposes the requested length", results[0]);
            because.ItsTrue("Memory exposes the requested length", results[1]);
            because.ItsTrue("Length reports the requested length", results[2]);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void GuardUseAfterDispose()
    {
        When.A<object>("throws on access after dispose and tolerates double dispose",
            new object(),
            (ignored) =>
            {
                SshRentedBuffer buffer = SshRentedBuffer.Rent(16);
                buffer.Dispose();
                bool spanThrows;
                try
                {
                    _ = buffer.Span;
                    spanThrows = false;
                }
                catch (ObjectDisposedException)
                {
                    spanThrows = true;
                }
                bool doubleDisposeSafe;
                try
                {
                    buffer.Dispose();
                    doubleDisposeSafe = true;
                }
                catch (Exception)
                {
                    doubleDisposeSafe = false;
                }
                return new bool[] { spanThrows, doubleDisposeSafe };
            })
        .TheTest
        .ShouldPass(because =>
        {
            bool[] results = (bool[])because.Result;
            because.ItsTrue("Span access after dispose throws ObjectDisposedException", results[0]);
            because.ItsTrue("a second dispose is a no-op", results[1]);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }
}
