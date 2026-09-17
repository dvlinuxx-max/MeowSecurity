using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using MeowSecurity.Core.Memory;
using MeowSecurity.Core.Network;
using MeowSecurity.Core.Processes;

using MeowSecurity.Core.Localization;

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

    /// <summary>What a process holds open and what runs inside it, as of the last deep pass.</summary>
    private readonly record struct DeepFacts(
        bool ReadsCredentialStore, int InjectionTargets, int ForeignThreads, bool ForeignThreadWritable);

    private readonly ConcurrentDictionary<int, Enrichment> _cache = new();
    private readonly ConcurrentDictionary<int, byte> _inFlight = new();
    private readonly InjectionScanner _injection = new();
    private readonly NetworkScanner _network = new();

    private volatile ConcurrentDictionary<int, DeepFacts> _deep = new();
    private DateTime _lastDeepPass = DateTime.MinValue;
    private int _deepRunning;

    /// <summary>
    /// How often the handle table and thread lists are re-read.
    ///
    /// Far slower than the UI tick, and deliberately so: one pass walks every handle on the
    /// machine and every thread in every process the user owns. At this cadence the cost
    /// disappears into the background, and none of what it looks for — a handle held open, a
    /// thread already running — is the kind of thing that comes and goes within a second.
    /// </summary>
    private static readonly TimeSpan DeepInterval = TimeSpan.FromSeconds(20);

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

            if (_deep.TryGetValue(row.Pid, out var d))
            {
                row.ReadsCredentialStore = d.ReadsCredentialStore;
                row.InjectionTargets = d.InjectionTargets;
                row.ForeignThreads = d.ForeignThreads;
                row.ForeignThreadWritable = d.ForeignThreadWritable;
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

    /// <summary>
    /// Re-reads the handle table and the thread lists, off the UI thread and at its own pace.
    ///
    /// Returns immediately if a pass is already running or the last one is still recent — the
    /// caller may invite this every tick without thinking about it. The result is published as
    /// a whole new map rather than mutated in place, so a reader on the UI thread always sees
    /// one consistent pass and never a half-updated one.
    /// </summary>
    public void DeepScanIfDue(IReadOnlyList<LiveProcess> rows)
    {
        if (DateTime.UtcNow - _lastDeepPass < DeepInterval) return;
        if (Interlocked.Exchange(ref _deepRunning, 1) == 1) return;

        int lsassPid = rows.FirstOrDefault(r =>
            r.Name.Equals("lsass.exe", StringComparison.OrdinalIgnoreCase))?.Pid ?? -1;
        var pids = rows.Where(r => r.Pid > 4 && r.Pid != OwnPid).Select(r => r.Pid).ToList();
        var parents = rows.ToDictionary(r => r.Pid, r => r.ParentPid);

        Task.Run(() =>
        {
            try { _deep = DeepScan(pids, parents, lsassPid); }
            catch { /* a pass that fails leaves the previous one standing */ }
            finally
            {
                _lastDeepPass = DateTime.UtcNow;
                Interlocked.Exchange(ref _deepRunning, 0);
            }
        });
    }

    private static ConcurrentDictionary<int, DeepFacts> DeepScan(
        List<int> pids, Dictionary<int, int> parents, int lsassPid)
    {
        var readsLsass = new HashSet<int>();
        var injectionTargets = new Dictionary<int, HashSet<int>>();

        // Whoever calls CreateProcess is handed a full-access handle to the child and keeps it
        // for the child's lifetime. Every browser, every shell and every terminal on the
        // machine therefore holds handles that look exactly like injection, and a rule that
        // counted them would fire on all of them at once — which is how a monitor gets muted.
        // A handle between a parent and its child is the ordinary cost of starting a program.
        bool SameFamily(int holder, int target) =>
            (parents.TryGetValue(target, out int tp) && tp == holder) ||
            (parents.TryGetValue(holder, out int hp) && hp == target);

        // One walk of the machine's handles answers both questions asked of it.
        foreach (var h in Native.HandleTable.ScanDangerous(out _))
        {
            if (lsassPid > 0 && h.TargetPid == lsassPid && h.CanReadMemory)
                readsLsass.Add(h.HolderPid);

            if (h.CanInject && !SameFamily(h.HolderPid, h.TargetPid))
            {
                if (!injectionTargets.TryGetValue(h.HolderPid, out var set))
                    injectionTargets[h.HolderPid] = set = [];
                set.Add(h.TargetPid);
            }
        }

        var facts = new ConcurrentDictionary<int, DeepFacts>();
        Parallel.ForEach(pids,
            new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount },
            pid =>
            {
                var foreign = Native.ThreadInspector.FindForeignThreads(pid);
                bool lsass = readsLsass.Contains(pid);
                int targets = injectionTargets.TryGetValue(pid, out var t) ? t.Count : 0;

                if (!lsass && targets == 0 && foreign.Count == 0) return;   // the usual case
                facts[pid] = new DeepFacts(lsass, targets, foreign.Count, foreign.Any(f => f.Writable));
            });

        return facts;
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
            reasons.Add(Strings.T("live.hidden"));
            return (Verdict.Suspicious, reasons);
        }

        string? path = imagePath?.ToLowerInvariant();
        bool inSystem = path is not null &&
            (path.StartsWith(WinDir) || path.Contains(@"\program files"));
        var verdict = Verdict.Safe;

        switch (sig)
        {
            case SignatureState.SignedInvalid:
                reasons.Add(Strings.T("autorun.bad-signature"));
                verdict = Verdict.Suspicious;
                break;
            case SignatureState.Unsigned when path is not null && !inSystem &&
                    (path.Contains(@"\temp\") || path.Contains(@"\appdata\local\temp")):
                reasons.Add(Strings.T("live.unsigned-temp"));
                verdict = Verdict.Suspicious;
                break;
            case SignatureState.Unsigned when path is not null && !inSystem:
                reasons.Add(Strings.T("live.unsigned-out"));
                verdict = Verdict.Review;
                break;
            default:
                if (sig is SignatureState.Unknown && !KnownSystem.Contains(name) && imagePath is null)
                    reasons.Add(Strings.T("live.opaque"));
                break;
        }

        if (implanted)
        {
            reasons.Add(Strings.T("live.implanted"));
            verdict = Verdict.Suspicious;
        }
        return (verdict, reasons);
    }
}
