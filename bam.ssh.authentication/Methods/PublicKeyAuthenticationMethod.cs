namespace Bam.Ssh.Authentication;

/// <summary>
/// The <c>publickey</c> authentication method (RFC 4252 §7). Sends a signed request directly (the
/// <c>has signature = TRUE</c> form): the signature covers the session identifier concatenated with the
/// request through the public-key blob, binding the proof to this session so it cannot be replayed. The
/// signature and public-key blob use the same wire encodings the transport host-key verifiers accept,
/// so a real server verifies this proof with the standard algorithm implementation.
/// </summary>
public sealed class PublicKeyAuthenticationMethod : ISshAuthenticationMethod
{
    private readonly ISshPrivateKey _privateKey;

    /// <summary>
    /// Initializes the method with the private key to authenticate with.
    /// </summary>
    /// <param name="privateKey">The client private key.</param>
    /// <exception cref="ArgumentNullException">The private key is null.</exception>
    public PublicKeyAuthenticationMethod(ISshPrivateKey privateKey)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        _privateKey = privateKey;
    }

    /// <inheritdoc/>
    public string MethodName => SshAuthenticationNames.PublicKey;

    /// <inheritdoc/>
    public async ValueTask<SshAuthenticationReply> AttemptAsync(ISshAuthenticationConversation conversation, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(conversation);

        byte[] publicKeyBlob = _privateKey.PublicKeyBlob.ToArray();
        byte[] sessionId = conversation.SessionId.ToArray();
        string userName = conversation.UserName;
        string serviceName = conversation.ServiceName;
        string algorithm = _privateKey.Algorithm;

        // The data signed for publickey auth (RFC 4252 §7): the session id followed by the request
        // fields up to and including the public-key blob. Building it here mirrors, byte for byte, the
        // request header the conversation frames around the method fields below.
        byte[] signedData = SshSignatureBlob.Build((ref SshWireWriter writer) =>
        {
            writer.WriteString(sessionId);
            writer.WriteByte((byte)SshMessageNumber.UserauthRequest);
            writer.WriteText(userName);
            writer.WriteText(serviceName);
            writer.WriteText(SshAuthenticationNames.PublicKey);
            writer.WriteBoolean(true);
            writer.WriteText(algorithm);
            writer.WriteString(publicKeyBlob);
        });

        byte[] signature = _privateKey.Sign(signedData);

        byte[] fields = SshSignatureBlob.Build((ref SshWireWriter writer) =>
        {
            writer.WriteBoolean(true);
            writer.WriteText(algorithm);
            writer.WriteString(publicKeyBlob);
            writer.WriteString(signature);
        });

        await conversation.SendRequestAsync(MethodName, fields, cancellationToken).ConfigureAwait(false);
        SshAuthenticationReply reply = await conversation.ReceiveReplyAsync(cancellationToken).ConfigureAwait(false);
        return SshAuthenticationMethodSupport.EnsureTerminal(reply, MethodName);
    }
}
