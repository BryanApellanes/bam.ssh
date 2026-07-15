namespace Bam.Ssh;

/// <summary>
/// SSH_MSG_DISCONNECT reason codes assigned by RFC 4250 §4.2.2. Sent in the 'reason code' field
/// of SSH_MSG_DISCONNECT (RFC 4253 §11.1) to indicate why a connection is being terminated.
/// </summary>
public enum SshDisconnectReason : uint
{
    /// <summary>No reason recorded. Not a wire value — used internally before a reason is assigned.</summary>
    None = 0,

    /// <summary>SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT — the host is administratively prohibited.</summary>
    HostNotAllowedToConnect = 1,

    /// <summary>SSH_DISCONNECT_PROTOCOL_ERROR — the peer violated the protocol (malformed packet, bad lengths).</summary>
    ProtocolError = 2,

    /// <summary>SSH_DISCONNECT_KEY_EXCHANGE_FAILED — key exchange could not complete.</summary>
    KeyExchangeFailed = 3,

    /// <summary>SSH_DISCONNECT_RESERVED — reserved value; must not be sent.</summary>
    Reserved = 4,

    /// <summary>SSH_DISCONNECT_MAC_ERROR — message authentication code verification failed.</summary>
    MacError = 5,

    /// <summary>SSH_DISCONNECT_COMPRESSION_ERROR — compressed data could not be processed.</summary>
    CompressionError = 6,

    /// <summary>SSH_DISCONNECT_SERVICE_NOT_AVAILABLE — the requested service is not offered.</summary>
    ServiceNotAvailable = 7,

    /// <summary>SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED — no mutually supported protocol version.</summary>
    ProtocolVersionNotSupported = 8,

    /// <summary>SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE — the host key could not be verified.</summary>
    HostKeyNotVerifiable = 9,

    /// <summary>SSH_DISCONNECT_CONNECTION_LOST — the underlying connection was lost.</summary>
    ConnectionLost = 10,

    /// <summary>SSH_DISCONNECT_BY_APPLICATION — the application requested the disconnect.</summary>
    ByApplication = 11,

    /// <summary>SSH_DISCONNECT_TOO_MANY_CONNECTIONS — the peer has too many simultaneous connections.</summary>
    TooManyConnections = 12,

    /// <summary>SSH_DISCONNECT_AUTH_CANCELLED_BY_USER — the user cancelled authentication.</summary>
    AuthCancelledByUser = 13,

    /// <summary>SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE — no remaining authentication methods.</summary>
    NoMoreAuthMethodsAvailable = 14,

    /// <summary>SSH_DISCONNECT_ILLEGAL_USER_NAME — the user name is not permitted.</summary>
    IllegalUserName = 15
}
