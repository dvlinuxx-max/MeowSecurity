using System.Security.Principal;
using System.Text;
using MeowSecurity.Cli;
using MeowSecurity.Core.Detect;
using MeowSecurity.Core.Intel;
using MeowSecurity.Core.Persistence;
using MeowSecurity.Core.Processes;

Console.OutputEncoding = Encoding.UTF8;

// Regression check for the behaviour rules. Detection logic cannot be validated by running
// real malware, so it is validated against a table of attack shapes and — just as important
// — a table of the everyday developer noise that must never fire.
if (args.Contains("--rule-test"))
{
    Environment.ExitCode = RuleTest.Run() ? 0 : 1;
    return;
}

// Live process-start feed straight from the kernel. This is also how the ETW plumbing gets
// verified: start it, run something short-lived, and watch it appear.
if (args.Contains("--watch"))
{
    using var watcher = new MeowSecurity.Core.Etw.ProcessStartWatcher();
    watcher.Started += p =>
        Console.WriteLine($"  {p.TimeUtc.ToLocalTime():HH:mm:ss.fff}  {p.Name,-28} pid {p.Pid,-6} " +
                          $"parent {p.ParentName ?? "?"} ({p.ParentPid})\n" +
                          $"        {p.ImagePath}\n" +
                          (p.CommandLine is null ? "" : $"        {p.CommandLine}\n"));

    if (!watcher.Start())
    {
        Console.WriteLine($"ETW unavailable: {watcher.Error}");
        Environment.ExitCode = 1;
        return;
    }

    int seconds = Idx("--watch") + 1 < args.Length && int.TryParse(args[Idx("--watch") + 1], out int s) ? s : 20;
    Console.WriteLine($"Watching process starts for {seconds}s (kernel ETW)\n" + new string('-', 78));

    // Per-process throughput, printed each second: the same counters the network page reads.
    for (int elapsed = 0; elapsed < seconds; elapsed++)
    {
        Thread.Sleep(1000);
        var totals = watcher.TakeNetworkTotals();
        var busiest = totals.OrderByDescending(t => t.Value.In + t.Value.Out).Take(4).ToList();
        if (busiest.Count == 0) continue;

        Console.WriteLine($"  [{elapsed + 1,2}s] network:");
        foreach (var (pid, bytes) in busiest)
        {
            string name;
            try { using var proc = System.Diagnostics.Process.GetProcessById(pid); name = proc.ProcessName; }
            catch { name = "?"; }
            Console.WriteLine($"         {name,-22} pid {pid,-6} down {Kb(bytes.In),9}  up {Kb(bytes.Out),9}");
        }
    }

    static string Kb(long b) => b >= 1024 * 1024 ? $"{b / 1024.0 / 1024:0.0} MB/s" : $"{b / 1024.0:0.0} KB/s";
    Console.WriteLine($"payload fields: {watcher.PayloadFields ?? "(no start event seen)"}");
    Console.WriteLine("done.");
    return;
}

// Who is holding whom open. The handle rules cannot be proven by the rule table — that only
// checks the judgement, not the reading — so this is how the reading itself gets verified,
// on a real machine, against processes whose behaviour is already known.
if (args.Contains("--handles"))
{
    var clock = System.Diagnostics.Stopwatch.StartNew();
    var handles = MeowSecurity.Core.Native.HandleTable.ScanDangerous(out int unreadable);
    clock.Stop();

    var names = new Dictionary<int, string>();
    var parents = new Dictionary<int, int>();
    foreach (var p in MeowSecurity.Core.Native.SystemProcessSnapshot.Enumerate())
    {
        names[p.Pid] = p.Name;
        parents[p.Pid] = p.ParentPid;
    }
    string Name(int pid) => names.TryGetValue(pid, out var n) ? n : "(exited)";

    // The handle a parent gets from CreateProcess looks identical to an injection handle, so
    // the listing says which is which rather than leaving the reader to guess.
    bool Family(int holder, int target) =>
        (parents.TryGetValue(target, out int tp) && tp == holder) ||
        (parents.TryGetValue(holder, out int hp) && hp == target);

    int lsass = names.FirstOrDefault(kv =>
        kv.Value.Equals("lsass.exe", StringComparison.OrdinalIgnoreCase)).Key;

    Console.WriteLine($"Cross-process handles — {handles.Count} found in {clock.ElapsedMilliseconds} ms");
    if (unreadable > 0)
        Console.WriteLine($"  {unreadable} holder(s) could not be opened — run elevated to see those too.");
    Console.WriteLine(new string('-', 78));

    int family = handles.Count(h => Family(h.HolderPid, h.TargetPid));
    Console.WriteLine($"  {family} of them are parent/child — the handle CreateProcess hands out, and not a finding.\n");

    foreach (var h in handles
        .OrderByDescending(h => h.TargetPid == lsass)
        .ThenBy(h => Family(h.HolderPid, h.TargetPid))
        .ThenBy(h => h.HolderPid))
    {
        var marks = new List<string>();
        if (h.CanReadMemory) marks.Add("read-memory");
        if (h.CanInject) marks.Add("inject");

        string flag =
            h.TargetPid == lsass && h.CanReadMemory ? "  <== CREDENTIAL STORE" :
            Family(h.HolderPid, h.TargetPid) ? "  (parent/child)" : "";

        Console.WriteLine(
            $"  {Name(h.HolderPid),-28} ({h.HolderPid,6}) -> {Name(h.TargetPid),-24} ({h.TargetPid,6})  " +
            $"0x{h.GrantedAccess:X6}  {string.Join('+', marks)}{flag}");
    }
    return;
}

// The companion to --handles: what is running inside every process, and whether any of it
// came from somewhere other than a file. On a clean machine this should print almost nothing,
// and that is the point of being able to run it.
if (args.Contains("--threads"))
{
    var clock = System.Diagnostics.Stopwatch.StartNew();
    var all = MeowSecurity.Core.Native.SystemProcessSnapshot.Enumerate();
    int examined = 0, blind = 0;
    var hits = new List<(string Name, int Pid, MeowSecurity.Core.Native.ForeignThread T)>();

    foreach (var p in all.Where(p => p.Pid > 4 && p.Pid != Environment.ProcessId))
    {
        var foreign = MeowSecurity.Core.Native.ThreadInspector.FindForeignThreads(p.Pid);
        if (foreign.Count == 0) { examined++; continue; }
        examined++;
        foreach (var t in foreign) hits.Add((p.Name, p.Pid, t));
    }
    clock.Stop();

    Console.WriteLine($"Threads starting outside any image — {all.Count} processes in {clock.ElapsedMilliseconds} ms");
    Console.WriteLine($"  {hits.Count} finding(s) across {hits.Select(h => h.Pid).Distinct().Count()} process(es).");
    Console.WriteLine(new string('-', 78));

    foreach (var g in hits.GroupBy(h => (h.Name, h.Pid)).OrderByDescending(g => g.Count()))
        Console.WriteLine(
            $"  {g.Key.Name,-28} ({g.Key.Pid,6})  {g.Count()} thread(s)" +
            (g.Any(h => h.T.Writable) ? "  <== writable+executable memory" : "") +
            $"   e.g. 0x{g.First().T.StartAddress:X}");

    if (hits.Count == 0) Console.WriteLine("  (nothing — the expected result on a clean machine)");
    _ = blind;
    return;
}

// What every process is running with, and what it has loaded. Like --handles and --threads,
// this prints the reading rather than the verdict: the rule table can only check that the
// judgement is right about its inputs, never that the inputs were true.
if (args.Contains("--tokens"))
{
    var clock = System.Diagnostics.Stopwatch.StartNew();
    var all = MeowSecurity.Core.Native.SystemProcessSnapshot.Enumerate();
    int unreadable = 0, sideloads = 0;
    var notable = new List<string>();

    var tokenClock = new System.Diagnostics.Stopwatch();
    var moduleClock = new System.Diagnostics.Stopwatch();

    foreach (var p in all.Where(p => p.Pid > 4 && p.Pid != Environment.ProcessId))
    {
        tokenClock.Start();
        var tok = MeowSecurity.Core.Native.TokenInspector.Read(p.Pid);
        tokenClock.Stop();
        if (tok.Integrity == MeowSecurity.Core.Native.IntegrityLevel.Unknown) { unreadable++; continue; }

        var marks = new List<string>();
        if (tok.DebugPrivilege) marks.Add("SeDebugPrivilege ENABLED");
        if (tok.Impersonating) marks.Add("impersonating");
        if (tok.IsSystem) marks.Add("SYSTEM");

        moduleClock.Start();
        var modules = MeowSecurity.Core.Native.ModuleInspector.FindUntrustedModules(p.Pid);
        moduleClock.Stop();
        foreach (var m in modules)
        {
            sideloads++;
            marks.Add($"untrusted module: {m.FilePath} ({m.Signature})");
        }

        if (marks.Count > 0 && !(marks.Count == 1 && tok.IsSystem))
            notable.Add($"  {p.Name,-28} ({p.Pid,6})  {tok.Integrity,-7}  {string.Join(" | ", marks)}");
    }
    clock.Stop();

    Console.WriteLine($"Tokens and loaded modules — {all.Count} processes in {clock.ElapsedMilliseconds} ms");
    Console.WriteLine($"  tokens {tokenClock.ElapsedMilliseconds} ms, modules {moduleClock.ElapsedMilliseconds} ms");
    Console.WriteLine($"  {unreadable} token(s) unreadable at this privilege level; {sideloads} untrusted module(s).");
    Console.WriteLine(new string('-', 78));
    foreach (var line in notable) Console.WriteLine(line);
    if (notable.Count == 0) Console.WriteLine("  (nothing notable)");
    return;
}

// Named pipes, by name only — this never connects to one. --all prints the whole listing,
// which is how the patterns get checked against a real machine's legitimate pipes rather than
// against a guess about them.
if (args.Contains("--pipes"))
{
    var all = MeowSecurity.Core.Native.NamedPipes.All();
    var suspect = MeowSecurity.Core.Native.NamedPipes.FindSuspect();

    Console.WriteLine($"Named pipes — {all.Count} open, {suspect.Count} matching known tooling");
    Console.WriteLine(new string('-', 78));

    foreach (var p in suspect)
        Console.WriteLine($"  {p.Name,-44}  {p.Framework}");
    if (suspect.Count == 0)
        Console.WriteLine("  (none — the expected result)");

    if (args.Contains("--all"))
    {
        Console.WriteLine($"\nAll {all.Count} pipe names:");
        foreach (var n in all.OrderBy(n => n, StringComparer.OrdinalIgnoreCase))
            Console.WriteLine($"  {n}");
    }
    return;
}

// Who can sign in to this machine, and who is signed in now.
if (args.Contains("--accounts"))
{
    var accounts = MeowSecurity.Core.Accounts.AccountScanner.Accounts();
    var sessions = MeowSecurity.Core.Accounts.AccountScanner.Sessions();

    Console.WriteLine($"Local accounts — {accounts.Count}");
    Console.WriteLine(new string('-', 78));
    foreach (var a in accounts.OrderByDescending(a => a.IsAdministrator).ThenBy(a => a.Name))
    {
        var marks = new List<string>();
        if (a.IsAdministrator) marks.Add("ADMIN");
        if (!a.IsEnabled) marks.Add("disabled");
        if (a.IsBuiltIn) marks.Add("built-in");
        if (a.PasswordNeverExpires) marks.Add("password never expires");

        string seen = a.LastLogon is null ? "never signed in" : $"last {a.LastLogon:yyyy-MM-dd HH:mm}";
        Console.WriteLine($"  {a.Name,-24}  {seen,-26}  {string.Join(", ", marks)}");
    }

    Console.WriteLine($"\nSessions — {sessions.Count}");
    Console.WriteLine(new string('-', 78));
    foreach (var s in sessions.OrderBy(s => s.SessionId))
        Console.WriteLine(
            $"  {s.SessionId,3}  {s.StationName,-16}  {s.State,-13}  " +
            $"{(s.User.Length == 0 ? "(nobody)" : s.User)}" +
            (s.ClientAddress is null ? "" : $"   from {s.ClientAddress}"));

    var findings = MeowSecurity.Core.Accounts.AccountRules.Evaluate(accounts, sessions);
    Console.WriteLine($"\nFindings — {findings.Count}");
    Console.WriteLine(new string('-', 78));
    foreach (var f in findings)
        Console.WriteLine($"  [{f.Severity,-8}] {f.Title}\n      {f.Detail}  [{f.Technique}]");
    if (findings.Count == 0) Console.WriteLine("  (none)");
    return;
}

// Times one second's worth of monitoring work, stage by stage, with no user interface
// attached. The product was measured taking a quarter of a core while sitting still, and two
// guesses about why were both wrong — so this splits the tick into its parts and makes the
// machine say which one costs what.
if (args.Contains("--bench"))
{
    int ticks = 20;
    int at = Array.IndexOf(args, "--bench");
    if (at + 1 < args.Length && int.TryParse(args[at + 1], out int n)) ticks = n;

    var sampler = new MeowSecurity.Core.Live.LiveSampler();
    var enricher = new MeowSecurity.Core.Live.LiveEnricher();
    var watcher = new BehaviorWatcher(new EventStore());

    var timers = new Dictionary<string, double>
    {
        ["sample"] = 0, ["overlay"] = 0, ["inspect"] = 0, ["machine"] = 0,
    };
    var clock = new System.Diagnostics.Stopwatch();
    int rows = 0;

    // One warm-up tick: the first pass pays for caches everything after it reuses.
    sampler.Sample(out _);

    double cpuBefore = System.Diagnostics.Process.GetCurrentProcess().TotalProcessorTime.TotalSeconds;
    var wall = System.Diagnostics.Stopwatch.StartNew();

    for (int i = 0; i < ticks; i++)
    {
        clock.Restart();
        var sample = sampler.Sample(out _);
        timers["sample"] += clock.Elapsed.TotalMilliseconds;
        rows = sample.Count;

        clock.Restart();
        enricher.Overlay(sample);
        timers["overlay"] += clock.Elapsed.TotalMilliseconds;

        clock.Restart();
        watcher.Inspect(sample);
        timers["inspect"] += clock.Elapsed.TotalMilliseconds;

        clock.Restart();
        watcher.InspectMachine();
        timers["machine"] += clock.Elapsed.TotalMilliseconds;

        enricher.EnrichMissing(sample, scanMemory: true);
        enricher.DeepScanIfDue(sample);

        Thread.Sleep(1000);

        // Pricing is meant to happen once per process. If this keeps climbing on an idle
        // machine, something is being re-priced that should already be cached.
        if (i == 4 || i == ticks - 1)
            Console.WriteLine($"  after tick {i + 1,3}: {enricher.PricedCount} processes priced so far");
    }

    wall.Stop();
    double cpuUsed = System.Diagnostics.Process.GetCurrentProcess().TotalProcessorTime.TotalSeconds - cpuBefore;

    Console.WriteLine($"Tick cost — {ticks} ticks over {rows} processes");
    Console.WriteLine(new string('-', 78));
    foreach (var (name, total) in timers.OrderByDescending(t => t.Value))
        Console.WriteLine($"  {name,-10}  {total / ticks,8:0.0} ms per tick   {total,9:0} ms total");

    Console.WriteLine(new string('-', 78));
    Console.WriteLine($"  process CPU: {cpuUsed:0.0}s over {wall.Elapsed.TotalSeconds:0}s wall " +
                      $"= {100 * cpuUsed / wall.Elapsed.TotalSeconds:0.0}% of one core");
    Console.WriteLine("  (background enrichment and the deep pass are included in the CPU figure");
    Console.WriteLine("   but not in the per-stage times, which measure only the tick itself.)");
    return;
}

if (args.Contains("--events"))
{
    var store = new EventStore();
    var log = store.Load(args.Contains("--all") ? EventStore.MaxEvents : 40);
    Console.WriteLine($"Security events — {log.Count} shown, {store.FilePath}\n" + new string('-', 78));
    foreach (var e in log)
        Console.WriteLine($"  {e.TimeLocal:yyyy-MM-dd HH:mm:ss}  [{e.Severity,-8}] {e.Process} ({e.Pid})\n" +
                          $"      {e.Title} — {e.Detail}  [{e.Technique ?? "-"}]");
    return;
}

// Switch one autorun on or off by name — the same code path the UI uses, so it is also how
// the behaviour gets verified without clicking through a context menu.
if (Array.IndexOf(args, "--autorun-off") is var offIdx and >= 0 && offIdx + 1 < args.Length ||
    Array.IndexOf(args, "--autorun-on") is var onIdx and >= 0 && onIdx + 1 < args.Length)
{
    bool enable = Array.IndexOf(args, "--autorun-on") >= 0;
    int idx = enable ? Array.IndexOf(args, "--autorun-on") : Array.IndexOf(args, "--autorun-off");
    string target = args[idx + 1];

    var match = new AutorunScanner().Scan()
        .FirstOrDefault(x => x.Name.Equals(target, StringComparison.OrdinalIgnoreCase));
    if (match is null)
    {
        Console.WriteLine($"No autorun named \"{target}\".");
        Environment.ExitCode = 1;
        return;
    }

    var result = AutorunControl.SetEnabled(match, enable);
    Console.WriteLine($"{match.Location} / {match.Name}: {(result.Ok ? "OK" : "FAILED")} — {result.Message}");
    Environment.ExitCode = result.Ok ? 0 : 1;
    return;
}

// Register or remove the "start with Windows" task. Same code path the settings switch uses.
if (args.Contains("--startup-status") || args.Contains("--startup-on") || args.Contains("--startup-off"))
{
    if (args.Contains("--startup-on"))
    {
        int i = Array.IndexOf(args, "--startup-on");
        string exe = i + 1 < args.Length && !args[i + 1].StartsWith('-')
            ? args[i + 1]
            : Environment.ProcessPath ?? "";
        var r = StartupRegistration.Register(exe);
        Console.WriteLine($"{(r.Ok ? "OK" : "FAILED")} — {r.Message}");
        Environment.ExitCode = r.Ok ? 0 : 1;
    }
    else if (args.Contains("--startup-off"))
    {
        var r = StartupRegistration.Unregister();
        Console.WriteLine($"{(r.Ok ? "OK" : "FAILED")} — {r.Message}");
        Environment.ExitCode = r.Ok ? 0 : 1;
    }

    Console.WriteLine($"registered: {StartupRegistration.IsRegistered()}");
    return;
}

if (args.Contains("--autoruns"))
{
    var ar = new AutorunScanner().Scan();
    Console.WriteLine($"Autoruns — {ar.Count} entries\n" + new string('-', 78));
    foreach (var e in ar.OrderByDescending(x => (int)x.Verdict))
        Console.WriteLine($"  [{e.Verdict,-10}] {(e.Enabled ? "on " : "OFF")} {e.Location,-16} {e.Name,-28} {e.Reason}\n" +
                          $"               {e.ImagePath}");
    return;
}

int Idx(string flag) => Array.IndexOf(args, flag);

// Optional plain-text mirror of the report, so an elevated launch can hand results back.
string? outPath = null;
for (int i = 0; i < args.Length - 1; i++)
    if (args[i] is "--out") outPath = args[i + 1];
var mirror = outPath is null ? null : new StringBuilder();

void Emit(string line = "")
{
    Console.WriteLine(line);
    mirror?.AppendLine(line);
}

bool elevated = IsElevated();
Emit($"Meow Security — process scan  ({(elevated ? "elevated" : "NOT elevated — some processes will be opaque")})");
Emit(new string('-', 78));

var scanner = new ProcessScanner();
var start = DateTime.UtcNow;
var processes = scanner.Scan();
var took = (DateTime.UtcNow - start).TotalMilliseconds;

int hidden = 0, suspicious = 0, review = 0;
foreach (var p in processes)
{
    if (p.IsHidden) hidden++;
    if (p.Verdict == Verdict.Suspicious) suspicious++;
    else if (p.Verdict == Verdict.Review) review++;
}

Emit("Flagged processes:");
Emit();
bool any = false;
foreach (var p in processes)
{
    if (p.Verdict == Verdict.Safe && p.Reasons.Count == 0) continue;
    any = true;
    Report(p);
}
if (!any)
    Emit("  none — every process is signed and enumerated consistently.\n");

Emit(new string('-', 78));
Emit($"{processes.Count} processes in {took:F0} ms   " +
     $"suspicious {suspicious} · review {review} · hidden {hidden}");
if (!elevated)
    Emit("Tip: run elevated (right-click > Run as administrator) for a full scan.");

if (outPath is not null && mirror is not null)
    File.WriteAllText(outPath, mirror.ToString(), Encoding.UTF8);

void Report(ProcessInfo p)
{
    var (color, tag) = p.Verdict switch
    {
        Verdict.Suspicious => (ConsoleColor.Red, "SUSPICIOUS"),
        Verdict.Review => (ConsoleColor.Yellow, "REVIEW"),
        _ => (ConsoleColor.DarkGray, "note"),
    };
    Console.ForegroundColor = color;
    Console.Write($"  [{tag,-10}]");
    Console.ResetColor();
    string name = string.IsNullOrEmpty(p.Name) ? "(unknown)" : p.Name;
    Console.WriteLine($" pid {p.Pid,-6} {name}");
    mirror?.AppendLine($"  [{tag,-10}] pid {p.Pid,-6} {name}");

    if (p.ImagePath is not null) Emit($"               {p.ImagePath}");
    if (p.Publisher is not null) Emit($"               publisher: {p.Publisher}");
    if (p.HasImplantedPe)
        Emit($"               memory: implanted PE in unbacked memory ({p.InjectedRegions} exec region(s))");
    if (p.RemoteConnections > 0)
        Emit($"               network: {p.RemoteConnections} active connection(s)");
    if (p.Reasons.Count > 0) Emit($"               why: {string.Join("; ", p.Reasons)}");
    Emit();
}

static bool IsElevated()
{
    try
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
    catch { return false; }
}
