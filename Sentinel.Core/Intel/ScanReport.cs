using System;

namespace Sentinel.Core.Intel;

/// <summary>
/// The result of an on-demand scan of a file or a URL — the shape the "Scan" page shows.
/// Distinct from <see cref="HashReputation"/> (which is the passive per-process verdict):
/// a scan is something the user deliberately asked for and may have uploaded content for.
/// </summary>
public sealed record ScanReport
{
    /// <summary>What was scanned — a file path or a URL.</summary>
    public required string Target { get; init; }
    public ScanKind Kind { get; init; }
    public ThreatLevel Level { get; init; } = ThreatLevel.Unknown;

    public int Malicious { get; init; }
    public int Suspicious { get; init; }
    public int Harmless { get; init; }
    public int Undetected { get; init; }
    public int TotalEngines => Malicious + Suspicious + Harmless + Undetected;

    public string? Family { get; init; }
    public string? Detail { get; init; }
    public string? Permalink { get; init; }
    public string Source { get; init; } = "VirusTotal";
    public DateTime AsOfUtc { get; init; } = DateTime.UtcNow;

    /// <summary>Set when the scan could not run (no key, quota exhausted, network) — surfaced to the user verbatim.</summary>
    public string? Error { get; init; }
    public bool Ok => Error is null;
}

public enum ScanKind { File, Url }
