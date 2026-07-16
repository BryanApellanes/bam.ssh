namespace Bam.Ssh.Authentication;

/// <summary>
/// A single keyboard-interactive prompt (RFC 4256 §3.3): the text to display and whether the user's
/// typed response should be echoed (false for passwords, true for visible fields).
/// </summary>
public sealed class SshKeyboardInteractivePrompt
{
    /// <summary>
    /// Initializes a prompt.
    /// </summary>
    /// <param name="prompt">The prompt text to display.</param>
    /// <param name="echo">Whether the response should be echoed as typed.</param>
    public SshKeyboardInteractivePrompt(string prompt, bool echo)
    {
        Prompt = prompt;
        Echo = echo;
    }

    /// <summary>Gets the prompt text.</summary>
    public string Prompt { get; }

    /// <summary>Gets a value indicating whether the response should be echoed.</summary>
    public bool Echo { get; }
}

/// <summary>
/// Answers keyboard-interactive challenges (RFC 4256). Given the request's name, instruction, and
/// prompts, returns one response per prompt in order. A common implementation simply returns the user's
/// password for a single non-echoed prompt.
/// </summary>
public interface ISshKeyboardInteractiveResponder
{
    /// <summary>
    /// Produces responses for a set of prompts.
    /// </summary>
    /// <param name="name">The request name (may be empty).</param>
    /// <param name="instruction">The request instruction (may be empty).</param>
    /// <param name="prompts">The prompts to answer, in order.</param>
    /// <returns>One response per prompt, in the same order.</returns>
    IReadOnlyList<string> Respond(string name, string instruction, IReadOnlyList<SshKeyboardInteractivePrompt> prompts);
}
