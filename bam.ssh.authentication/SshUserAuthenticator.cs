using System.Diagnostics;
using Bam.Ssh.Transport;

namespace Bam.Ssh.Authentication;

/// <summary>
/// Drives the client role of RFC 4252 user authentication over an established, encrypted
/// <see cref="SshTransport"/>: requests the <c>ssh-userauth</c> service, then tries a caller-supplied
/// ordered list of <see cref="ISshAuthenticationMethod"/> until one succeeds or all are exhausted. It
/// owns the packet receive loop, handling the generic replies (SUCCESS, FAILURE, and transparently
/// BANNER) centrally while handing method-specific messages (60–79) to the running method through the
/// <see cref="ISshAuthenticationConversation"/> seam it implements. Not thread-safe; one dialog at a
/// time.
/// </summary>
public sealed class SshUserAuthenticator : ISshAuthenticationConversation
{
    private readonly SshTransport _transport;
    private readonly byte[] _sessionId;
    private readonly ISshBannerSink _bannerSink;
    private readonly ISshLogger _logger;
    private string _userName = string.Empty;

    /// <summary>
    /// Initializes the authenticator.
    /// </summary>
    /// <param name="transport">The connected, keyed transport (key exchange must have completed).</param>
    /// <param name="sessionId">The session identifier from key exchange (binds publickey signatures).</param>
    /// <param name="bannerSink">Receives pre-auth banners; defaults to <see cref="NullSshBannerSink.Instance"/>.</param>
    /// <param name="logger">The logger; defaults to <see cref="NullSshLogger.Instance"/>.</param>
    /// <exception cref="ArgumentNullException">The transport or session id is null.</exception>
    public SshUserAuthenticator(
        SshTransport transport,
        byte[] sessionId,
        ISshBannerSink? bannerSink = null,
        ISshLogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(sessionId);
        _transport = transport;
        _sessionId = sessionId;
        _bannerSink = bannerSink ?? NullSshBannerSink.Instance;
        _logger = logger ?? NullSshLogger.Instance;
    }

    /// <inheritdoc/>
    public ReadOnlyMemory<byte> SessionId => _sessionId;

    /// <inheritdoc/>
    public string UserName => _userName;

    /// <inheritdoc/>
    public string ServiceName => SshAuthenticationNames.ConnectionService;

    /// <summary>
    /// Authenticates the given user, trying each method in order until one succeeds.
    /// </summary>
    /// <param name="userName">The user name to authenticate.</param>
    /// <param name="methods">The methods to try, in preference order.</param>
    /// <param name="cancellationToken">Cancels the dialog.</param>
    /// <returns>The authentication outcome.</returns>
    /// <exception cref="ArgumentNullException">The user name or methods list is null.</exception>
    /// <exception cref="SshAuthenticationException">The service was refused or a reply was malformed.</exception>
    public async ValueTask<SshAuthenticationResult> AuthenticateAsync(
        string userName,
        IReadOnlyList<ISshAuthenticationMethod> methods,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(userName);
        ArgumentNullException.ThrowIfNull(methods);
        using Activity? activity = SshActivitySource.Instance.StartActivity("ssh.user_auth");
        _userName = userName;

        await RequestUserAuthServiceAsync(cancellationToken).ConfigureAwait(false);

        SshNameList lastContinue = SshNameList.Empty;
        bool lastPartial = false;
        foreach (ISshAuthenticationMethod method in methods)
        {
            if (_logger.IsEnabled(SshLogLevel.Information))
            {
                _logger.Log(SshLogLevel.Information, "Attempting authentication method '{0}' for user '{1}'.", method.MethodName, userName);
            }

            SshAuthenticationReply reply = await method.AttemptAsync(this, cancellationToken).ConfigureAwait(false);
            if (reply.Kind == SshAuthenticationReplyKind.Success)
            {
                if (_logger.IsEnabled(SshLogLevel.Information))
                {
                    _logger.Log(SshLogLevel.Information, "Authentication succeeded via '{0}'.", method.MethodName);
                }
                return new SshAuthenticationResult(true, method.MethodName, Array.Empty<string>(), false);
            }

            lastContinue = reply.MethodsThatCanContinue;
            lastPartial = reply.PartialSuccess;
        }

        return new SshAuthenticationResult(false, null, lastContinue.Names, lastPartial);
    }

    /// <inheritdoc/>
    public async ValueTask SendRequestAsync(string methodName, ReadOnlyMemory<byte> methodFields, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(methodName);
        using PooledBufferWriter writer = new PooledBufferWriter(64 + methodFields.Length);
        SshWireWriter wire = new SshWireWriter(writer);
        wire.WriteByte((byte)SshMessageNumber.UserauthRequest);
        wire.WriteText(_userName);
        wire.WriteText(ServiceName);
        wire.WriteText(methodName);
        wire.WriteRaw(methodFields.Span);
        await _transport.SendPacketAsync(writer.WrittenMemory, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async ValueTask SendMethodSpecificAsync(byte messageNumber, ReadOnlyMemory<byte> body, CancellationToken cancellationToken = default)
    {
        using PooledBufferWriter writer = new PooledBufferWriter(1 + body.Length);
        SshWireWriter wire = new SshWireWriter(writer);
        wire.WriteByte(messageNumber);
        wire.WriteRaw(body.Span);
        await _transport.SendPacketAsync(writer.WrittenMemory, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public async ValueTask<SshAuthenticationReply> ReceiveReplyAsync(CancellationToken cancellationToken = default)
    {
        while (true)
        {
            using SshIncomingPacket packet = await _transport.ReceivePacketAsync(cancellationToken).ConfigureAwait(false);
            if (packet.IsEmpty)
            {
                throw new SshAuthenticationException("Received an empty packet during authentication.");
            }

            byte messageNumber = packet.MessageNumber;
            switch ((SshMessageNumber)messageNumber)
            {
                case SshMessageNumber.UserauthSuccess:
                    return SshAuthenticationReply.CreateSuccess();
                case SshMessageNumber.UserauthFailure:
                    return ParseFailure(packet.Body);
                case SshMessageNumber.UserauthBanner:
                    HandleBanner(packet.Body);
                    continue;
                default:
                    return SshAuthenticationReply.CreateMethodSpecific(messageNumber, packet.Body.ToArray());
            }
        }
    }

    private async ValueTask RequestUserAuthServiceAsync(CancellationToken cancellationToken)
    {
        using (PooledBufferWriter writer = new PooledBufferWriter(32))
        {
            SshWireWriter wire = new SshWireWriter(writer);
            wire.WriteByte((byte)SshMessageNumber.ServiceRequest);
            wire.WriteText(SshAuthenticationNames.UserAuthService);
            await _transport.SendPacketAsync(writer.WrittenMemory, cancellationToken).ConfigureAwait(false);
        }

        using SshIncomingPacket packet = await _transport.ReceivePacketAsync(cancellationToken).ConfigureAwait(false);
        if (packet.IsEmpty || packet.MessageNumber != (byte)SshMessageNumber.ServiceAccept)
        {
            byte actual = packet.IsEmpty ? (byte)0 : packet.MessageNumber;
            throw new SshAuthenticationException($"Expected SSH_MSG_SERVICE_ACCEPT (6) but received {actual}.");
        }

        try
        {
            SshWireReader reader = new SshWireReader(packet.Body);
            string acceptedService = reader.ReadText();
            if (acceptedService != SshAuthenticationNames.UserAuthService)
            {
                throw new SshAuthenticationException($"The server accepted service '{acceptedService}' instead of '{SshAuthenticationNames.UserAuthService}'.");
            }
        }
        catch (SshWireFormatException exception)
        {
            throw new SshAuthenticationException("The SSH_MSG_SERVICE_ACCEPT message was malformed.", exception);
        }
    }

    private static SshAuthenticationReply ParseFailure(ReadOnlySpan<byte> body)
    {
        try
        {
            SshWireReader reader = new SshWireReader(body);
            SshNameList methodsThatCanContinue = reader.ReadNameList();
            bool partialSuccess = reader.ReadBoolean();
            return SshAuthenticationReply.CreateFailure(methodsThatCanContinue, partialSuccess);
        }
        catch (SshWireFormatException exception)
        {
            throw new SshAuthenticationException("An SSH_MSG_USERAUTH_FAILURE message was malformed.", exception);
        }
    }

    private void HandleBanner(ReadOnlySpan<byte> body)
    {
        try
        {
            SshWireReader reader = new SshWireReader(body);
            string message = reader.ReadText();
            string languageTag = reader.ReadText();
            _bannerSink.OnBanner(message, languageTag);
        }
        catch (SshWireFormatException exception)
        {
            throw new SshAuthenticationException("An SSH_MSG_USERAUTH_BANNER message was malformed.", exception);
        }
    }
}
