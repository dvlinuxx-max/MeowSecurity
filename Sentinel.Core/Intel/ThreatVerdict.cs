using System;

namespace Sentinel.Core.Intel;

/// <summary>
/// Where a reputation verdict came from and how much weight it carries.
/// The order matters: a later source only overrides an earlier one when it
/// speaks with more authority (Malicious always wins, KnownGood clears noise).
/// </summary>
public enum ThreatLevel
{
    /// <summary>No source had anything to say about this file.</summary>
    Unknown = 0,
    /// <summary>Present in a known-good database (NSRL / CIRCL) — a legitimate, shipped file.</summary>
    KnownGood = 1,
    /// <summary>Local heuristics raised a flag but no reputation source confirmed it.</summary>
    Suspicious = 2,
    /// <summary>A reputation source (MalwareBazaar / VirusTotal) says this is malware.</summary>
    Malicious = 3,
}

/// <summary>
/// The distilled reputation of one file, merged across every intel source we asked.
/// This is what the UI colours a row by, and what the on-disk cache stores.
/// </summary>
public sealed record HashReputation
{
    public required string Sha256 { get; init; }
    public ThreatLevel Level { get; init; } = ThreatLevel.Unknown;

    /// <summary>Human-facing one-liner, e.g. "Trojan.Emotet — 48/72 engines" or "Known Windows file (NSRL)".</summary>
    public string? Detail { get; init; }

    /// <summary>Malware family/label when a source names one.</summary>
    public string? Family { get; init; }

    /// <summary>Engines that flagged it / total engines, when a multi-engine source (VT) answered.</summary>
    public int Detections { get; init; }
    public int TotalEngines { get; init; }

    /// <summary>Which source produced the winning verdict ("CIRCL", "MalwareBazaar", "VirusTotal", "cache").</summary>
    public string Source { get; init; } = "";

    /// <summary>A link a human can open to see the full report, when the source offers one.</summary>
    public string? Permalink { get; init; }

    /// <summary>When this verdict was produced (UTC). Drives cache freshness.</summary>
    public DateTime AsOfUtc { get; init; } = DateTime.UtcNow;

    public static HashReputation UnknownFor(string sha256) =>
        new() { Sha256 = sha256, Level = ThreatLevel.Unknown, Source = "" };
}
