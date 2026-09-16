namespace MeowSecurity.Core.Detect;

/// <summary>How loudly a detection should speak. Drives colour, sorting and whether it pops up.</summary>
public enum Severity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

/// <summary>
/// One behavioural finding about a process — the *why*, not the *what*.
///
/// A detection is deliberately small and self-describing: a title the user can read,
/// the evidence that produced it, an ATT&amp;CK technique id for anyone who speaks that
/// language, and a weight. The engine emits several of these per process and the caller
/// adds the weights up, because no single living-off-the-land signal is proof on its own
/// — a chain of them is.
/// </summary>
/// <param name="Rule">Stable rule id, e.g. "lolbin.encoded-command". Used for dedupe.</param>
/// <param name="Severity">How serious this single signal is.</param>
/// <param name="Score">Weight added to the process's total threat score (0-100 scale).</param>
/// <param name="Title">Short Arabic headline shown in the events timeline.</param>
/// <param name="Detail">The concrete evidence — a parent name, a command-line fragment, a path.</param>
/// <param name="Technique">MITRE ATT&amp;CK technique id, or null when the rule maps to none.</param>
public sealed record Detection(
    string Rule,
    Severity Severity,
    int Score,
    string Title,
    string Detail,
    string? Technique = null);
