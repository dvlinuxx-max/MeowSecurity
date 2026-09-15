using Sentinel.Core.Processes;

namespace Sentinel.Core.Live;

/// <summary>How a process is coloured in the list, mirroring a task-monitor's conventions.</summary>
public enum ProcessKind
{
    Normal,
    System,   // session-0 OS process
    Service,  // hosted by services.exe
    Own,      // Sentinel's own process tree
}

/// <summary>
/// A single process as of one live tick: fast counters (CPU, memory, I/O, threads) computed
/// every sample, plus slower security fields (signature, verdict, connections) that a
/// background pass fills in and this snapshot carries forward from the cache.
/// </summary>
public sealed class LiveProcess
{
    public int Pid { get; init; }
    public int ParentPid { get; init; }
    public int SessionId { get; init; }
    public required string Name { get; init; }

    public int Threads { get; init; }
    public int Handles { get; init; }
    public double CpuPercent { get; set; }
    public long WorkingSet { get; init; }
    public long PrivateBytes { get; init; }
    public long IoBytesPerSec { get; set; }

    public ProcessKind Kind { get; set; }

    // Filled by background enrichment; carried across ticks via the cache.
    public string? ImagePath { get; set; }
    public string? CommandLine { get; set; }
    public string? Publisher { get; set; }
    public string? Description { get; set; }
    public SignatureState Signature { get; set; }
    public Verdict Verdict { get; set; }
    public int Connections { get; set; }
    public int RemoteConnections { get; set; }
    public bool HasImplantedPe { get; set; }
    public bool IsHidden { get; set; }
    public IReadOnlyList<string> Reasons { get; set; } = [];
}

/// <summary>Machine-wide totals for the header graphs and status bar.</summary>
public readonly record struct SystemPulse(
    double CpuPercent,
    long MemoryUsed,
    long MemoryTotal,
    long NetInBytesPerSec,
    long NetOutBytesPerSec,
    int ProcessCount,
    int ThreadCount);
