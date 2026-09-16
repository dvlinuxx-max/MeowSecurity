using MeowSecurity.Core.Live;

namespace MeowSecurity.Core.Detect;

/// <summary>
/// Runs the behaviour engine over every live tick and turns new findings into events.
///
/// Two things make this harder than "evaluate and log". First, enrichment is asynchronous:
/// a process appears with nothing but a name, and its path, signature and command line land
/// a beat later — so the same process must be re-judged as the evidence arrives. Second, a
/// monitor that repeats itself every second is worse than useless, so we remember which
/// rules already fired for each PID and only raise what is genuinely new.
/// </summary>
public sealed class BehaviorWatcher
{
    private readonly EventStore _store;
    private readonly Dictionary<int, HashSet<string>> _reported = [];

    /// <summary>Below this, findings are recorded but never interrupt the user.</summary>
    public Severity AlertFloor { get; set; } = Severity.High;

    public BehaviorWatcher(EventStore store) => _store = store;

    /// <summary>
    /// Judges the current process list and returns only the events that are new this tick.
    /// Cheap enough for the one-second UI tick: local string work, no I/O beyond the append.
    /// </summary>
    /// <summary>
    /// Judges a single process the instant the kernel reports it, before the next poll — and
    /// before it has a chance to exit. Shares the per-PID dedupe with the polling pass, so a
    /// process caught here is not reported a second time a tick later.
    ///
    /// Called from an ETW thread, hence the lock.
    /// </summary>
    public SecurityEvent? InspectOne(ProcessContext ctx)
    {
        lock (_gate)
        {
            var result = BehaviorEngine.Evaluate(ctx);
            if (result.IsEmpty) return null;

            if (!_reported.TryGetValue(ctx.Pid, out var already))
                _reported[ctx.Pid] = already = [];

            var novel = result.Detections.Where(d => !already.Contains(d.Rule)).ToList();
            if (novel.Count == 0) return null;
            foreach (var d in novel) already.Add(d.Rule);

            var ev = SecurityEvent.From(result with { Detections = novel });
            _store.Append(ev);
            return ev;
        }
    }

    private readonly Lock _gate = new();

    public List<SecurityEvent> Inspect(IReadOnlyList<LiveProcess> rows)
    {
        lock (_gate)
        {
            return InspectCore(rows);
        }
    }

    private List<SecurityEvent> InspectCore(IReadOnlyList<LiveProcess> rows)
    {
        var namesByPid = new Dictionary<int, string>(rows.Count);
        foreach (var r in rows) namesByPid[r.Pid] = r.Name;

        var fresh = new List<SecurityEvent>();

        foreach (var row in rows)
        {
            // Our own process would otherwise flag itself while it reads other processes.
            if (row.Kind == ProcessKind.Own) continue;

            namesByPid.TryGetValue(row.ParentPid, out var parentName);

            var result = BehaviorEngine.Evaluate(new ProcessContext(
                row.Pid, row.Name, row.ParentPid, parentName,
                row.ImagePath, row.CommandLine, row.Signature,
                row.IsHidden, row.HasImplantedPe, row.RemoteConnections, row.SessionId));

            if (result.IsEmpty) continue;

            if (!_reported.TryGetValue(row.Pid, out var already))
                _reported[row.Pid] = already = [];

            // Only the rules we have not already told the user about for this PID.
            var novel = result.Detections.Where(d => !already.Contains(d.Rule)).ToList();
            if (novel.Count == 0) continue;
            foreach (var d in novel) already.Add(d.Rule);

            var ev = SecurityEvent.From(result with { Detections = novel });
            _store.Append(ev);
            fresh.Add(ev);
        }

        // Forget exited processes so a long-running session cannot grow without bound.
        if (_reported.Count > rows.Count)
        {
            var alive = new HashSet<int>(namesByPid.Keys);
            foreach (var pid in _reported.Keys.Where(p => !alive.Contains(p)).ToList())
                _reported.Remove(pid);
        }

        return fresh;
    }
}
