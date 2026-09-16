using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using MeowSecurity.Core.Memory;
using MeowSecurity.Core.Network;
using MeowSecurity.Core.Processes;

namespace MeowSecurity.Core.Live;

/// <summary>
/// The slow half of the monitor. Signature verification and memory scanning are far too
/// expensive to run on every process every tick, so they run on a background pass and land
/// in a per-PID cache. Each live tick just overlays that cache (plus fresh, cheap network
/// data) onto the rows, so security verdicts appear a beat after a process shows up.
/// </summary>
public sealed class LiveEnricher
{
    private sealed record Enrichment(
        string? ImagePath, string? CommandLine, string? Publisher, string? Description,
        SignatureState Signature, Verdict Verdict, bool HasImplantedPe,
        IReadOnlyList<string> Reasons);

    private readonly ConcurrentDictionary<int, Enrichment> _cache = new();
    private readonly ConcurrentDictionary<int, byte> _inFlight = new();
    private readonly InjectionScanner _injection = new();
    private readonly NetworkScanner _network = new();

    private static readonly string WinDir =
        Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLowerInvariant();
    private static readonly int OwnPid = Environment.ProcessId;

    /// <summary>Overlay cached security data + fresh connections + row colour. Fast, on the UI tick.</summary>
    public void Overlay(IReadOnlyList<LiveProcess> rows)
    {
        var connsByPid = _network.Scan()
            .GroupBy(c => c.Pid)
            .ToDictionary(g => g.Key, g => g.ToList());

        int servicesPid = rows.FirstOrDefault(r =>
            r.Name.Equals("services.exe", StringComparison.OrdinalIgnoreCase))?.Pid ?? -1;
        var live = new HashSet<int>(rows.Count);

        foreach (var row in rows)
        {
            live.Add(row.Pid);

            if (_cache.TryGetValue(row.Pid, out var e))
            {
                row.ImagePath = e.ImagePath;
                row.CommandLine = e.CommandLine;
                row.Publisher = e.Publisher;
                row.Description = e.Description;
                row.Signature = e.Signature;
                row.Verdict = e.Verdict;
                row.HasImplantedPe = e.HasImplantedPe;
                row.Reasons = e.Reasons;
            }

            if (connsByPid.TryGetValue(row.Pid, out var conns))
            {
                row.Connections = conns.Count;
                row.RemoteConnections = conns.Count(c =>
                    !c.IsListener && c.Remote is not null &&
                    !c.Remote.Address.Equals(IPAddress.Any) && c.Remote.Port != 0);
            }
            else
            {
                row.Connections = 0;
                row.RemoteConnections = 0;
            }

            row.Kind =
                row.Pid == OwnPid ? ProcessKind.Own :
                (servicesPid > 0 && row.ParentPid == servicesPid) ? ProcessKind.Service :
                row.SessionId == 0 ? ProcessKind.System :
                ProcessKind.Normal;
        }

        // Forget processes that have exited so the cache can't grow without bound.
        foreach (var pid in _cache.Keys)
            if (!live.Contains(pid)) _cache.TryRemove(pid, out _);
    }

    /// <summary>Kick a background pass for any PID we haven't priced yet. Non-blocking.</summary>
    public void EnrichMissing(IReadOnlyList<LiveProcess> rows, bool scanMemory)
    {
        var todo = rows.Where(r => !_cache.ContainsKey(r.Pid) && _inFlight.TryAdd(r.Pid, 0))
                       .Select(r => (r.Pid, r.Name, r.IsHidden, r.SessionId))
                       .ToList();
        if (todo.Count == 0) return;

        Task.Run(() =>
        {
            Parallel.ForEach(todo,
                new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount },
                item =>
                {
                    try { _cache[item.Pid] = Price(item.Pid, item.Name, item.IsHidden, scanMemory); }
                    catch { /* protected process — leave uncached, retry next pass */ }
                    finally { _inFlight.TryRemove(item.Pid, out _); }
                });
        });
    }

    private Enrichment Price(int pid, string name, bool hidden, bool scanMemory)
    {
        string? publisher = null, description = null;
        var signature = SignatureState.Unknown;

        // Limited-information query first: it succeeds for nearly every process without
        // elevation, where MainModule would have failed and left the row blank.
        string? path = Native.ProcessDetails.GetImagePath(pid);
        if (path is null)
        {
            try { using var p = Process.GetProcessById(pid); path = p.MainModule?.FileName; }
            catch { /* protected process — no path, and therefore no verdict */ }
        }

        if (path is not null)
        {
            var (state, pub) = SignatureCache.Get(path);
            signature = state;
            publisher = pub;
            try
            {
                var info = FileVersionInfo.GetVersionInfo(path);
                description = info.FileDescription;
                // Catalog-signed Windows binaries carry no embedded certificate, so the
                // publisher column would sit empty for most of the OS. The version resource
                // names the same company, and says so for unsigned files too.
                if (string.IsNullOrWhiteSpace(publisher)) publisher = Nz(info.CompanyName);
            }
            catch { /* no version resource */ }
        }

        string? commandLine = pid > 4 ? Native.ProcessDetails.GetCommandLine(pid) : null;

        bool implanted = false;
        if (scanMemory && pid > 4)
        {
            try { implanted = _injection.Scan(pid).Any(r => r.HasPeHeader); }
            catch { }
        }

        var (verdict, reasons) = Score(name, path, signature, hidden, implanted);
        return new Enrichment(path, commandLine, publisher, description, signature, verdict, implanted, reasons);
    }

    private static string? Nz(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();

    private static readonly HashSet<string> KnownSystem = new(StringComparer.OrdinalIgnoreCase)
    {
        "System Idle Process", "System", "Registry", "Secure System", "MemCompression",
        "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
        "lsass.exe", "svchost.exe", "fontdrvhost.exe", "dwm.exe", "LsaIso.exe",
    };

    // Same evidence-based scoring as the on-demand scanner: flag only on positive signals.
    private static (Verdict, List<string>) Score(
        string name, string? imagePath, SignatureState sig, bool hidden, bool implanted)
    {
        var reasons = new List<string>();
        if (hidden)
        {
            reasons.Add("مخفية عن أحد مصدري تعداد العمليات");
            return (Verdict.Suspicious, reasons);
        }

        string? path = imagePath?.ToLowerInvariant();
        bool inSystem = path is not null &&
            (path.StartsWith(WinDir) || path.Contains(@"\program files"));
        var verdict = Verdict.Safe;

        switch (sig)
        {
            case SignatureState.SignedInvalid:
                reasons.Add("توقيع رقمي غير صالح");
                verdict = Verdict.Suspicious;
                break;
            case SignatureState.Unsigned when path is not null && !inSystem &&
                    (path.Contains(@"\temp\") || path.Contains(@"\appdata\local\temp")):
                reasons.Add("غير موقعة وتعمل من مجلد مؤقت");
                verdict = Verdict.Suspicious;
                break;
            case SignatureState.Unsigned when path is not null && !inSystem:
                reasons.Add("غير موقعة خارج مجلدات النظام");
                verdict = Verdict.Review;
                break;
            default:
                if (sig is SignatureState.Unknown && !KnownSystem.Contains(name) && imagePath is null)
                    reasons.Add("تعذر الفحص (شغل بصلاحية المدير)");
                break;
        }

        if (implanted)
        {
            reasons.Add("وحدة PE تعمل من ذاكرة غير مدعومة — كود محقون على الأرجح");
            verdict = Verdict.Suspicious;
        }
        return (verdict, reasons);
    }
}
