namespace MeowSecurity.Core.Processes;

public enum Verdict { Safe, Review, Suspicious }

public enum SignatureState { Unknown, Unsigned, SignedValid, SignedInvalid }

/// <summary>One process as the monitor sees it, with the signals we scored it on.</summary>
public sealed class ProcessInfo
{
    public required int Pid { get; init; }
    public int ParentPid { get; init; }
    public required string Name { get; set; }
    public string? ImagePath { get; internal set; }
    public string? Publisher { get; internal set; }
    public SignatureState Signature { get; internal set; } = SignatureState.Unknown;

    /// <summary>Seen by the Toolhelp snapshot (managed Process class).</summary>
    public bool SeenByToolhelp { get; set; }
    /// <summary>Seen by ntdll's NtQuerySystemInformation.</summary>
    public bool SeenByNtQuery { get; set; }

    /// <summary>Present in one enumeration source but not the other — a hiding signal.</summary>
    public bool IsHidden => SeenByToolhelp ^ SeenByNtQuery;

    /// <summary>Unbacked executable memory regions — injection / shellcode signals.</summary>
    public int InjectedRegions { get; internal set; }
    public long InjectedBytes { get; internal set; }
    /// <summary>Any private read-write-execute region — weak on its own (JIT engines use it).</summary>
    public bool HasPrivateRwx { get; internal set; }
    /// <summary>A PE header sits in unbacked executable memory — a real implanted module.</summary>
    public bool HasImplantedPe { get; internal set; }

    /// <summary>Active network endpoints this process owns (established + listeners).</summary>
    public int Connections { get; internal set; }
    public int RemoteConnections { get; internal set; }

    public Verdict Verdict { get; set; } = Verdict.Review;
    public List<string> Reasons { get; } = [];
}
