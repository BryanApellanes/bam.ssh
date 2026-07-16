using System.Diagnostics;
using Bam.Ssh.Transport;

namespace Bam.Ssh.Authentication;

/// <summary>
/// Drives the server role of RFC 4252 user authentication over an established, encrypted transport: it
/// accepts the <c>ssh-userauth</c> service, then loops receiving SSH_MSG_USERAUTH_REQUEST and delegates
/// the accept/reject decision to the configured <see cref="ISshPasswordAuthenticator"/> and
/// <see cref="ISshPublicKeyAuthenticator"/> policies. Publickey requests are checked two ways — the
/// policy authorizes the key, and the request signature is verified against the session-id-bound blob
/// with the production transport verifier (<see cref="SshHostKeyParser"/>) — so a forged signature is
/// rejected even for an authorized key. The structural mirror of <see cref="SshUserAuthenticator"/>.
/// </summary>
public sealed class SshServerAuthenticator
{
    private readonly SshTransport _transport;
    private readonly byte[] _sessionId;
    private readonly ISshPasswordAuthenticator? _password;
    private readonly ISshPublicKeyAuthenticator? _publicKey;
    private readonly string? _banner;
    private readonly ISshLogger _logger;
    private readonly SshNameList _continueMethods;

    /// <summary>
    /// Initializes the server authenticator.
    /// </summary>
    /// <param name="transport">The connected, keyed transport.</param>
    /// <param name="sessionId">The session identifier from key exchange (binds publickey signatures).</param>
    /// <param name="password">The password policy, or null to refuse password authentication.</param>
    /// <param name="publicKey">The publickey policy, or null to refuse publickey authentication.</param>
    /// <param name="banner">An optional pre-authentication banner.</param>
    /// <param name="logger">The logger; defaults to <see cref="NullSshLogger.Instance"/>.</param>
    /// <exception cref="ArgumentNullException">The transport or session id is null.</exception>
    /// <exception cref="SshAuthenticationException">No authentication method is configured.</exception>
    public SshServerAuthenticator(
        SshTransport transport,
        byte[] sessionId,
        ISshPasswordAuthenticator? password = null,
        ISshPublicKeyAuthenticator? publicKey = null,
        string? banner = null,
        ISshLogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(sessionId);
        if (password == null && publicKey == null)
        {
            throw new SshAuthenticationException("At least one authentication policy must be configured.");
        }
        _transport = transport;
        _sessionId = sessionId;
        _password = password;
        _publicKey = publicKey;
        _banner = banner;
        _logger = logger ?? NullSshLogger.Instance;

        List<string> methods = new List<string>();
        if (publicKey != null)
        {
            methods.Add(SshAuthenticationNames.PublicKey);
        }
        if (password != null)
        {
            methods.Add(SshAuthenticationNames.Password);
        }
        _continueMethods = new SshNameList(methods.ToArray());
    }

    /// <summary>
    /// Runs the server authentication dialog until a method succeeds.
    /// </summary>
    /// <param name="cancellationToken">Cancels the dialog.</param>
    /// <returns>The successful authentication's user and method.</returns>
    /// <exception cref="SshAuthenticationException">A message was malformed or the service was not requested.</exception>
    public async ValueTask<SshServerAuthenticationResult> AuthenticateAsync(CancellationToken cancellationToken = default)
    {
        using Activity? activity = SshActivitySource.Instance.StartActivity("ssh.user_auth.server");

        await AcceptServiceAsync(cancellationToken).ConfigureAwait(false);
        if (_banner != null)
        {
            await SendBannerAsync(_banner, cancellationToken).ConfigureAwait(false);
        }

        while (true)
        {
            AuthenticationRequest request = await ReceiveRequestAsync(cancellationToken).ConfigureAwait(false);

            if (request.Kind == AuthenticationRequestKind.PublicKeyQuery)
            {
                bool authorized = _publicKey != null
                    && await _publicKey.IsAuthorizedAsync(request.UserName, request.Algorithm!, request.PublicKeyBlob, cancellationToken).ConfigureAwait(false);
                if (authorized)
                {
                    await SendPublicKeyOkAsync(request.Algorithm!, request.PublicKeyBlob, cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    await SendFailureAsync(cancellationToken).ConfigureAwait(false);
                }
                continue;
            }

            bool accepted = await EvaluateAsync(request, cancellationToken).ConfigureAwait(false);
            if (accepted)
            {
                await SendAsync(new byte[] { (byte)SshMessageNumber.UserauthSuccess }, cancellationToken).ConfigureAwait(false);
                if (_logger.IsEnabled(SshLogLevel.Information))
                {
                    _logger.Log(SshLogLevel.Information, "User '{0}' authenticated via '{1}'.", request.UserName, request.Method);
                }
                return new SshServerAuthenticationResult(request.UserName, request.Method);
            }
            await SendFailureAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private async ValueTask<bool> EvaluateAsync(AuthenticationRequest request, CancellationToken cancellationToken)
    {
        switch (request.Kind)
        {
            case AuthenticationRequestKind.Password:
                return _password != null
                    && await _password.AuthenticateAsync(request.UserName, request.Password!, cancellationToken).ConfigureAwait(false);
            case AuthenticationRequestKind.PublicKeySigned:
                if (_publicKey == null)
                {
                    return false;
                }
                bool authorized = await _publicKey.IsAuthorizedAsync(request.UserName, request.Algorithm!, request.PublicKeyBlob, cancellationToken).ConfigureAwait(false);
                return authorized && VerifySignature(request);
            default:
                return false;
        }
    }

    private bool VerifySignature(AuthenticationRequest request)
    {
        byte[] signedData = BuildSignedData(request);
        ISshHostKey verifier = SshHostKeyParser.Parse(request.PublicKeyBlob.Span);
        return verifier.Verify(signedData, request.Signature!);
    }

    private byte[] BuildSignedData(AuthenticationRequest request)
    {
        using PooledBufferWriter writer = new PooledBufferWriter(256);
        SshWireWriter wire = new SshWireWriter(writer);
        wire.WriteString(_sessionId);
        wire.WriteByte((byte)SshMessageNumber.UserauthRequest);
        wire.WriteText(request.UserName);
        wire.WriteText(SshAuthenticationNames.ConnectionService);
        wire.WriteText(SshAuthenticationNames.PublicKey);
        wire.WriteBoolean(true);
        wire.WriteText(request.Algorithm!);
        wire.WriteString(request.PublicKeyBlob.Span);
        return writer.WrittenSpan.ToArray();
    }

    private async ValueTask<AuthenticationRequest> ReceiveRequestAsync(CancellationToken cancellationToken)
    {
        using SshIncomingPacket packet = await _transport.ReceivePacketAsync(cancellationToken).ConfigureAwait(false);
        if (packet.IsEmpty || packet.MessageNumber != (byte)SshMessageNumber.UserauthRequest)
        {
            byte actual = packet.IsEmpty ? (byte)0 : packet.MessageNumber;
            throw new SshAuthenticationException($"Expected SSH_MSG_USERAUTH_REQUEST (50) but received {actual}.");
        }
        return ParseRequest(packet.Body);
    }

    private AuthenticationRequest ParseRequest(ReadOnlySpan<byte> body)
    {
        try
        {
            SshWireReader reader = new SshWireReader(body);
            string user = reader.ReadText();
            reader.ReadText(); // service name
            string method = reader.ReadText();

            if (method == SshAuthenticationNames.Password)
            {
                reader.ReadBoolean(); // change-password flag (unsupported: treated as a normal attempt)
                string password = reader.ReadText();
                return AuthenticationRequest.ForPassword(user, password);
            }
            if (method == SshAuthenticationNames.PublicKey)
            {
                bool hasSignature = reader.ReadBoolean();
                string algorithm = reader.ReadText();
                byte[] blob = reader.ReadString().ToArray();
                if (!hasSignature)
                {
                    return AuthenticationRequest.ForPublicKeyQuery(user, algorithm, blob);
                }
                byte[] signature = reader.ReadString().ToArray();
                return AuthenticationRequest.ForPublicKeySigned(user, algorithm, blob, signature);
            }
            return AuthenticationRequest.ForUnsupported(user, method);
        }
        catch (SshWireFormatException exception)
        {
            throw new SshAuthenticationException("An SSH_MSG_USERAUTH_REQUEST message was malformed.", exception);
        }
    }

    private async ValueTask AcceptServiceAsync(CancellationToken cancellationToken)
    {
        using SshIncomingPacket packet = await _transport.ReceivePacketAsync(cancellationToken).ConfigureAwait(false);
        if (packet.IsEmpty || packet.MessageNumber != (byte)SshMessageNumber.ServiceRequest)
        {
            byte actual = packet.IsEmpty ? (byte)0 : packet.MessageNumber;
            throw new SshAuthenticationException($"Expected SSH_MSG_SERVICE_REQUEST (5) but received {actual}.");
        }

        string requested;
        try
        {
            SshWireReader reader = new SshWireReader(packet.Body);
            requested = reader.ReadText();
        }
        catch (SshWireFormatException exception)
        {
            throw new SshAuthenticationException("The SSH_MSG_SERVICE_REQUEST message was malformed.", exception);
        }
        if (requested != SshAuthenticationNames.UserAuthService)
        {
            throw new SshAuthenticationException($"The client requested service '{requested}' instead of '{SshAuthenticationNames.UserAuthService}'.");
        }

        using PooledBufferWriter writer = new PooledBufferWriter(32);
        SshWireWriter wire = new SshWireWriter(writer);
        wire.WriteByte((byte)SshMessageNumber.ServiceAccept);
        wire.WriteText(SshAuthenticationNames.UserAuthService);
        await SendAsync(writer.WrittenSpan.ToArray(), cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask SendBannerAsync(string message, CancellationToken cancellationToken)
    {
        using PooledBufferWriter writer = new PooledBufferWriter(64);
        SshWireWriter wire = new SshWireWriter(writer);
        wire.WriteByte((byte)SshMessageNumber.UserauthBanner);
        wire.WriteText(message);
        wire.WriteText(string.Empty);
        await SendAsync(writer.WrittenSpan.ToArray(), cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask SendFailureAsync(CancellationToken cancellationToken)
    {
        using PooledBufferWriter writer = new PooledBufferWriter(64);
        SshWireWriter wire = new SshWireWriter(writer);
        wire.WriteByte((byte)SshMessageNumber.UserauthFailure);
        wire.WriteNameList(_continueMethods);
        wire.WriteBoolean(false);
        await SendAsync(writer.WrittenSpan.ToArray(), cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask SendPublicKeyOkAsync(string algorithm, ReadOnlyMemory<byte> publicKeyBlob, CancellationToken cancellationToken)
    {
        using PooledBufferWriter writer = new PooledBufferWriter(64 + publicKeyBlob.Length);
        SshWireWriter wire = new SshWireWriter(writer);
        wire.WriteByte(SshUserAuthMessageNumber.PublicKeyOk);
        wire.WriteText(algorithm);
        wire.WriteString(publicKeyBlob.Span);
        await SendAsync(writer.WrittenSpan.ToArray(), cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask SendAsync(byte[] payload, CancellationToken cancellationToken)
    {
        await _transport.SendPacketAsync(payload, cancellationToken).ConfigureAwait(false);
    }

    private enum AuthenticationRequestKind
    {
        Unsupported,
        Password,
        PublicKeyQuery,
        PublicKeySigned,
    }

    private sealed class AuthenticationRequest
    {
        private AuthenticationRequest(AuthenticationRequestKind kind, string userName, string method)
        {
            Kind = kind;
            UserName = userName;
            Method = method;
        }

        public AuthenticationRequestKind Kind { get; }

        public string UserName { get; }

        public string Method { get; }

        public string? Password { get; private init; }

        public string? Algorithm { get; private init; }

        public ReadOnlyMemory<byte> PublicKeyBlob { get; private init; }

        public byte[]? Signature { get; private init; }

        public static AuthenticationRequest ForPassword(string user, string password) =>
            new AuthenticationRequest(AuthenticationRequestKind.Password, user, SshAuthenticationNames.Password) { Password = password };

        public static AuthenticationRequest ForPublicKeyQuery(string user, string algorithm, byte[] blob) =>
            new AuthenticationRequest(AuthenticationRequestKind.PublicKeyQuery, user, SshAuthenticationNames.PublicKey) { Algorithm = algorithm, PublicKeyBlob = blob };

        public static AuthenticationRequest ForPublicKeySigned(string user, string algorithm, byte[] blob, byte[] signature) =>
            new AuthenticationRequest(AuthenticationRequestKind.PublicKeySigned, user, SshAuthenticationNames.PublicKey) { Algorithm = algorithm, PublicKeyBlob = blob, Signature = signature };

        public static AuthenticationRequest ForUnsupported(string user, string method) =>
            new AuthenticationRequest(AuthenticationRequestKind.Unsupported, user, method);
    }
}
