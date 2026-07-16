using Bam.Ssh.Authentication;
using Bam.Ssh.Client;
using Bam.Ssh.Server;
using Bam.Ssh.Transport;

namespace Bam.Ssh.Tests.Unit;

/// <summary>
/// Drives a production <see cref="SshClient"/> against a production <see cref="SshServer"/> over one
/// loopback transport: the server accepts the injected server stream (version exchange, key exchange,
/// authentication, connection) while the body runs the client's connect/authenticate/execute sequence, so a
/// single test exercises both real endpoints of the whole stack. Both sides are torn down on completion.
/// </summary>
internal static class ServerTestSupport
{
    public static T Run<T>(Action<SshServer> configure, Func<SshClient, ISshDuplexStream, Task<T>> body)
    {
        (LoopbackDuplexStream clientStream, LoopbackDuplexStream serverStream) = LoopbackDuplexStream.CreatePair();
        SshServer server = new SshServer();
        configure(server);
        CancellationTokenSource serverCancellation = new CancellationTokenSource();
        Task<SshServerSession> acceptTask = server.AcceptAsync(serverStream, serverCancellation.Token).AsTask();
        SshClient client = new SshClient(new SshClientOptions(AcceptAllHostKeyVerifier.Instance));
        try
        {
            return body(client, clientStream).GetAwaiter().GetResult();
        }
        finally
        {
            serverCancellation.Cancel();
            try
            {
                SshServerSession session = acceptTask.GetAwaiter().GetResult();
                session.DisposeAsync().AsTask().GetAwaiter().GetResult();
            }
            catch (Exception)
            {
                // The server may have been cancelled mid-handshake; teardown is best-effort.
            }
            client.DisposeAsync().AsTask().GetAwaiter().GetResult();
            server.DisposeAsync().AsTask().GetAwaiter().GetResult();
            serverCancellation.Dispose();
        }
    }

    public static byte[] MakeSeed(byte fill)
    {
        byte[] seed = new byte[32];
        Array.Fill(seed, fill);
        return seed;
    }

    public static async Task<byte[]> ReadAllAsync(Func<Memory<byte>, CancellationToken, ValueTask<int>> read, CancellationToken cancellationToken = default)
    {
        using MemoryStream buffer = new MemoryStream();
        byte[] rented = new byte[4096];
        while (true)
        {
            int count = await read(rented, cancellationToken).ConfigureAwait(false);
            if (count == 0)
            {
                return buffer.ToArray();
            }
            buffer.Write(rented, 0, count);
        }
    }
}

/// <summary>
/// A password policy that accepts exactly one user/password pair.
/// </summary>
internal sealed class FixedPasswordAuthenticator : ISshPasswordAuthenticator
{
    private readonly string _userName;
    private readonly string _password;

    public FixedPasswordAuthenticator(string userName, string password)
    {
        _userName = userName;
        _password = password;
    }

    public ValueTask<bool> AuthenticateAsync(string userName, string password, CancellationToken cancellationToken = default)
    {
        bool ok = string.Equals(userName, _userName, StringComparison.Ordinal)
            && string.Equals(password, _password, StringComparison.Ordinal);
        return ValueTask.FromResult(ok);
    }
}

/// <summary>
/// A publickey policy that authorizes exactly one public-key blob.
/// </summary>
internal sealed class FixedPublicKeyAuthenticator : ISshPublicKeyAuthenticator
{
    private readonly byte[] _authorizedBlob;

    public FixedPublicKeyAuthenticator(ReadOnlyMemory<byte> authorizedBlob)
    {
        _authorizedBlob = authorizedBlob.ToArray();
    }

    public ValueTask<bool> IsAuthorizedAsync(string userName, string algorithm, ReadOnlyMemory<byte> publicKeyBlob, CancellationToken cancellationToken = default)
    {
        return ValueTask.FromResult(publicKeyBlob.Span.SequenceEqual(_authorizedBlob));
    }
}
