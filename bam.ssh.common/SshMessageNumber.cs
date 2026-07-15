namespace Bam.Ssh;

/// <summary>
/// SSH message numbers assigned by RFC 4250 §4.1. The message number is the first byte of every
/// packet payload and identifies the message type. Ranges: 1–19 transport generic, 20–29 algorithm
/// negotiation, 30–49 key-exchange-method-specific, 50–59 user authentication generic,
/// 60–79 authentication-method-specific, 80–89 connection protocol generic, 90–127 channel messages.
/// </summary>
public enum SshMessageNumber : byte
{
    /// <summary>SSH_MSG_DISCONNECT (RFC 4253 §11.1) — the sender is terminating the connection.</summary>
    Disconnect = 1,

    /// <summary>SSH_MSG_IGNORE (RFC 4253 §11.2) — must be ignored; usable as a traffic-analysis countermeasure.</summary>
    Ignore = 2,

    /// <summary>SSH_MSG_UNIMPLEMENTED (RFC 4253 §11.4) — reply to an unrecognized message number.</summary>
    Unimplemented = 3,

    /// <summary>SSH_MSG_DEBUG (RFC 4253 §11.3) — debugging information that may be displayed or ignored.</summary>
    Debug = 4,

    /// <summary>SSH_MSG_SERVICE_REQUEST (RFC 4253 §10) — requests a service such as ssh-userauth.</summary>
    ServiceRequest = 5,

    /// <summary>SSH_MSG_SERVICE_ACCEPT (RFC 4253 §10) — grants a previously requested service.</summary>
    ServiceAccept = 6,

    /// <summary>SSH_MSG_KEXINIT (RFC 4253 §7.1) — begins algorithm negotiation.</summary>
    KexInit = 20,

    /// <summary>SSH_MSG_NEWKEYS (RFC 4253 §7.3) — signals that subsequent packets use the newly negotiated keys.</summary>
    NewKeys = 21,

    /// <summary>Key-exchange-method-specific message 30 (e.g. SSH_MSG_KEXDH_INIT for Diffie-Hellman, SSH_MSG_KEX_ECDH_INIT for ECDH).</summary>
    KexExchangeSpecific30 = 30,

    /// <summary>Key-exchange-method-specific message 31 (e.g. SSH_MSG_KEXDH_REPLY for Diffie-Hellman, SSH_MSG_KEX_ECDH_REPLY for ECDH).</summary>
    KexExchangeSpecific31 = 31,

    /// <summary>SSH_MSG_USERAUTH_REQUEST (RFC 4252 §5) — requests authentication with a named method.</summary>
    UserauthRequest = 50,

    /// <summary>SSH_MSG_USERAUTH_FAILURE (RFC 4252 §5.1) — authentication rejected; lists methods that can continue.</summary>
    UserauthFailure = 51,

    /// <summary>SSH_MSG_USERAUTH_SUCCESS (RFC 4252 §5.1) — authentication has completed successfully.</summary>
    UserauthSuccess = 52,

    /// <summary>SSH_MSG_USERAUTH_BANNER (RFC 4252 §5.4) — a banner message to display before authentication.</summary>
    UserauthBanner = 53,

    /// <summary>SSH_MSG_GLOBAL_REQUEST (RFC 4254 §4) — a request independent of any channel (e.g. tcpip-forward).</summary>
    GlobalRequest = 80,

    /// <summary>SSH_MSG_REQUEST_SUCCESS (RFC 4254 §4) — a global request succeeded.</summary>
    RequestSuccess = 81,

    /// <summary>SSH_MSG_REQUEST_FAILURE (RFC 4254 §4) — a global request failed.</summary>
    RequestFailure = 82,

    /// <summary>SSH_MSG_CHANNEL_OPEN (RFC 4254 §5.1) — requests opening a new channel.</summary>
    ChannelOpen = 90,

    /// <summary>SSH_MSG_CHANNEL_OPEN_CONFIRMATION (RFC 4254 §5.1) — the channel open was accepted.</summary>
    ChannelOpenConfirmation = 91,

    /// <summary>SSH_MSG_CHANNEL_OPEN_FAILURE (RFC 4254 §5.1) — the channel open was rejected.</summary>
    ChannelOpenFailure = 92,

    /// <summary>SSH_MSG_CHANNEL_WINDOW_ADJUST (RFC 4254 §5.2) — grants the peer additional flow-control window.</summary>
    ChannelWindowAdjust = 93,

    /// <summary>SSH_MSG_CHANNEL_DATA (RFC 4254 §5.2) — channel payload data.</summary>
    ChannelData = 94,

    /// <summary>SSH_MSG_CHANNEL_EXTENDED_DATA (RFC 4254 §5.2) — typed channel data such as stderr.</summary>
    ChannelExtendedData = 95,

    /// <summary>SSH_MSG_CHANNEL_EOF (RFC 4254 §5.3) — no more data will be sent on the channel.</summary>
    ChannelEof = 96,

    /// <summary>SSH_MSG_CHANNEL_CLOSE (RFC 4254 §5.3) — the sender has closed the channel.</summary>
    ChannelClose = 97,

    /// <summary>SSH_MSG_CHANNEL_REQUEST (RFC 4254 §5.4) — a channel-specific request (pty-req, exec, shell, …).</summary>
    ChannelRequest = 98,

    /// <summary>SSH_MSG_CHANNEL_SUCCESS (RFC 4254 §5.4) — a channel request succeeded.</summary>
    ChannelSuccess = 99,

    /// <summary>SSH_MSG_CHANNEL_FAILURE (RFC 4254 §5.4) — a channel request failed.</summary>
    ChannelFailure = 100
}
