using System.Diagnostics;
using System.Net;
using Sentinel.Core.Memory;
using Sentinel.Core.Native;
using Sentinel.Core.Network;

namespace Sentinel.Core.Processes;

/// <summary>
/// Builds the unified process view: enumerate through two independent sources, merge by
/// PID, flag anything that appears in only one (a hiding signal), then score each entry.
/// </summary>
public sealed class ProcessScanner
{
    private static readonly string WinDir =
        Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLowerInvariant();

    private readonly InjectionScanner _injection = new();
    private readonly NetworkScanner _network = new();

    /// <summary>Scan process memory for injected code too (slower, needs elevation).</summary>
    public bool ScanMemory { get; init; } = true;

    public IReadOnlyList<ProcessInfo> Scan()
    {
        var byPid = new Dictionary<int, ProcessInfo>();

        // Network endpoints grouped by owning PID, folded into each process below.
        var connsByPid = _network.Scan()
            .GroupBy(c => c.Pid)
            .ToDictionary(g => g.Key, g => g.ToList());

        // Source A: NtQuerySystemInformation (low-level, via ntdll).
        foreach (var rec in ProcessQuery.FromNtQuery())
            GetOrAdd(byPid, rec.Pid, rec.Name, rec.ParentPid).SeenByNtQuery = true;

        // Source B: the Toolhelp snapshot the managed Process class uses.
        foreach (var p in Process.GetProcesses())
        {
            using (p)
                GetOrAdd(byPid, p.Id, SafeName(p), 0).SeenByToolhelp = true;
        }

        var results = byPid.Values.ToList();

        // Signature verification dominates the scan time, so do it in parallel across
        // processes. The cache means repeated images (svchost, RuntimeBroker) cost once.
        Parallel.ForEach(results,
            new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount },
            Enrich);

        foreach (var info in results)
        {
            if (connsByPid.TryGetValue(info.Pid, out var conns))
            {
                info.Connections = conns.Count;
                info.RemoteConnections = conns.Count(c =>
                    !c.IsListener && c.Remote is not null &&
                    !c.Remote.Address.Equals(IPAddress.Any) && c.Remote.Port != 0);
            }
            Score(info);
        }

        results.Sort((a, b) => a.Pid.CompareTo(b.Pid));
        return results;
    }

    private static ProcessInfo GetOrAdd(Dictionary<int, ProcessInfo> map, int pid, string name, int ppid)
    {
        if (map.TryGetValue(pid, out var existing))
        {
            if (string.IsNullOrEmpty(existing.Name) && !string.IsNullOrEmpty(name))
                existing.Name = name;
            return existing;
        }
        var info = new ProcessInfo { Pid = pid, Name = name, ParentPid = ppid };
        map[pid] = info;
        return info;
    }

    private void Enrich(ProcessInfo info)
    {
        // QueryFullProcessImageName only needs PROCESS_QUERY_LIMITED_INFORMATION, so it
        // answers for ordinary processes even when we are not elevated. MainModule needs
        // PROCESS_VM_READ and fails there, which used to leave most rows with no path —
        // and so no signature and no publisher — on a normal user account.
        string? path = Native.ProcessDetails.GetImagePath(info.Pid);
        if (path is null)
        {
            try { using var p = Process.GetProcessById(info.Pid); path = p.MainModule?.FileName; }
            catch { /* protected process — expected without a driver */ }
        }

        if (path is not null)
        {
            var (state, publisher) = SignatureCache.Get(path);
            info.ImagePath = path;
            info.Signature = state;
            info.Publisher = publisher;
            if (string.IsNullOrWhiteSpace(info.Publisher))
            {
                // Catalog-signed Windows files carry no embedded certificate; the version
                // resource names the same company and covers unsigned files too.
                try
                {
                    var company = FileVersionInfo.GetVersionInfo(path).CompanyName;
                    if (!string.IsNullOrWhiteSpace(company)) info.Publisher = company.Trim();
                }
                catch { /* no version resource */ }
            }
        }

        if (ScanMemory && info.Pid > 4)
        {
            var regions = _injection.Scan(info.Pid);
            info.InjectedRegions = regions.Count;
            info.InjectedBytes = regions.Sum(r => r.Size);
            info.HasPrivateRwx = regions.Any(r => r.Rwx);
            info.HasImplantedPe = regions.Any(r => r.HasPeHeader);
        }
    }

    // Session-0 / boot processes that legitimately have no readable image path without a
    // driver. We must not flag these just because we couldn't open them.
    private static readonly HashSet<string> KnownSystem = new(StringComparer.OrdinalIgnoreCase)
    {
        "System Idle Process", "System", "Registry", "Secure System", "MemCompression",
        "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
        "lsass.exe", "svchost.exe", "fontdrvhost.exe", "dwm.exe", "LsaIso.exe",
    };

    // A process is flagged only on positive evidence. Absence of evidence (couldn't read
    // the image without elevation) is never, by itself, a reason to alarm the user.
    private void Score(ProcessInfo info)
    {
        if (info.IsHidden)
        {
            info.Reasons.Add(info.SeenByNtQuery
                ? "hidden from the Toolhelp snapshot"
                : "hidden from the native process list");
            info.Verdict = Verdict.Suspicious;
            return;
        }

        string? path = info.ImagePath?.ToLowerInvariant();
        bool inSystem = path is not null &&
            (path.StartsWith(WinDir) || path.Contains(@"\program files"));

        // Base verdict from the image's signature and origin.
        switch (info.Signature)
        {
            case SignatureState.SignedInvalid:
                info.Reasons.Add("digital signature does not validate");
                info.Verdict = Verdict.Suspicious;
                break;

            case SignatureState.Unsigned when path is not null && !inSystem &&
                    (path.Contains(@"\temp\") || path.Contains(@"\appdata\local\temp")):
                info.Reasons.Add("unsigned, running from a temp folder");
                info.Verdict = Verdict.Suspicious;
                break;

            case SignatureState.Unsigned when path is not null && !inSystem:
                info.Reasons.Add("unsigned, outside system folders");
                info.Verdict = Verdict.Review;
                break;

            default:
                info.Verdict = Verdict.Safe;
                if (info.Signature is SignatureState.Unknown && !KnownSystem.Contains(info.Name)
                        && info.ImagePath is null)
                    info.Reasons.Add("could not inspect (run elevated for a full scan)");
                break;
        }

        // Injected-code weighting. Trusted runtimes (.NET, browsers, Electron, Java) fill
        // memory with JIT code, so bare "unbacked executable memory" — even RWX — is NOT a
        // reliable signal, for signed OR unsigned processes. The reliable one is a PE header
        // living in unbacked memory: an implanted / reflectively-loaded / hollowed module,
        // which JIT never produces. That escalates regardless of signature.
        if (info.HasImplantedPe)
        {
            info.Reasons.Add("a PE module is running from unbacked memory — likely reflective/injected code");
            info.Verdict = Verdict.Suspicious;
        }
    }

    private static string SafeName(Process p)
    {
        try { return p.ProcessName + ".exe"; } catch { return string.Empty; }
    }
}
