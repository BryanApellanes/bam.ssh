namespace Bam.Ssh.Authentication;

/// <summary>
/// The <c>keyboard-interactive</c> authentication method (RFC 4256). After the initial request the
/// server drives one or more SSH_MSG_USERAUTH_INFO_REQUEST rounds, each carrying prompts the client
/// answers via an <see cref="ISshKeyboardInteractiveResponder"/>; the client replies with
/// SSH_MSG_USERAUTH_INFO_RESPONSE until the server returns success or failure.
/// </summary>
public sealed class KeyboardInteractiveAuthenticationMethod : ISshAuthenticationMethod
{
    private readonly ISshKeyboardInteractiveResponder _responder;
    private readonly string _submethods;

    /// <summary>
    /// Initializes the method with the responder that answers prompts.
    /// </summary>
    /// <param name="responder">Answers the server's prompts.</param>
    /// <param name="submethods">
    /// A comma-separated hint of preferred submethods (usually empty), sent in the initial request.
    /// </param>
    /// <exception cref="ArgumentNullException">The responder is null.</exception>
    public KeyboardInteractiveAuthenticationMethod(ISshKeyboardInteractiveResponder responder, string submethods = "")
    {
        ArgumentNullException.ThrowIfNull(responder);
        ArgumentNullException.ThrowIfNull(submethods);
        _responder = responder;
        _submethods = submethods;
    }

    /// <inheritdoc/>
    public string MethodName => SshAuthenticationNames.KeyboardInteractive;

    /// <inheritdoc/>
    public async ValueTask<SshAuthenticationReply> AttemptAsync(ISshAuthenticationConversation conversation, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(conversation);
        string submethods = _submethods;
        byte[] fields = SshSignatureBlob.Build((ref SshWireWriter writer) =>
        {
            writer.WriteText(string.Empty); // language tag (deprecated, empty)
            writer.WriteText(submethods);
        });
        await conversation.SendRequestAsync(MethodName, fields, cancellationToken).ConfigureAwait(false);

        while (true)
        {
            SshAuthenticationReply reply = await conversation.ReceiveReplyAsync(cancellationToken).ConfigureAwait(false);
            if (reply.Kind != SshAuthenticationReplyKind.MethodSpecific)
            {
                return SshAuthenticationMethodSupport.EnsureTerminal(reply, MethodName);
            }
            if (reply.MessageNumber != SshUserAuthMessageNumber.InformationRequest)
            {
                throw new SshAuthenticationException(
                    $"The 'keyboard-interactive' method received an unexpected method-specific message {reply.MessageNumber}.");
            }

            byte[] response = BuildInfoResponse(reply.Body.Span);
            await conversation.SendMethodSpecificAsync(SshUserAuthMessageNumber.InformationResponse, response, cancellationToken).ConfigureAwait(false);
        }
    }

    private byte[] BuildInfoResponse(ReadOnlySpan<byte> requestBody)
    {
        string name;
        string instruction;
        List<SshKeyboardInteractivePrompt> prompts = new List<SshKeyboardInteractivePrompt>();
        try
        {
            SshWireReader reader = new SshWireReader(requestBody);
            name = reader.ReadText();
            instruction = reader.ReadText();
            reader.ReadString(); // language tag
            uint promptCount = reader.ReadUInt32();
            for (uint i = 0; i < promptCount; i++)
            {
                string promptText = reader.ReadText();
                bool echo = reader.ReadBoolean();
                prompts.Add(new SshKeyboardInteractivePrompt(promptText, echo));
            }
        }
        catch (SshWireFormatException exception)
        {
            throw new SshAuthenticationException("A keyboard-interactive INFO_REQUEST was malformed.", exception);
        }

        IReadOnlyList<string> responses = _responder.Respond(name, instruction, prompts);
        if (responses.Count != prompts.Count)
        {
            throw new SshAuthenticationException(
                $"The keyboard-interactive responder returned {responses.Count} responses for {prompts.Count} prompts.");
        }

        return SshSignatureBlob.Build((ref SshWireWriter writer) =>
        {
            writer.WriteUInt32((uint)responses.Count);
            for (int i = 0; i < responses.Count; i++)
            {
                writer.WriteText(responses[i]);
            }
        });
    }
}
