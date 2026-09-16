using System.Security.Principal;
using System.Text;
using Sentinel.Cli;
using Sentinel.Core.Detect;
using Sentinel.Core.Intel;
using Sentinel.Core.Persistence;
using Sentinel.Core.Processes;

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
    using var watcher = new Sentinel.Core.Etw.ProcessStartWatcher();
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

// Threat-intel probes. These exercise the same reputation stack the GUI uses.
int Idx(string flag) => Array.IndexOf(args, flag);

if (args.Contains("--intel-status"))
{
    var s = IntelSettings.Load();
    Console.WriteLine("Threat intel configuration");
    Console.WriteLine(new string('-', 40));
    Console.WriteLine($"  Online lookups : {(s.OnlineLookupsEnabled ? "on" : "off")}");
    Console.WriteLine($"  CIRCL hashlookup: always on (keyless)");
    Console.WriteLine($"  MalwareBazaar   : {(string.IsNullOrWhiteSpace(s.EffectiveAbuseChKey) ? "no key (skipped)" : "key present")}");
    Console.WriteLine($"  VirusTotal      : {(s.HasVirusTotal ? "enabled (BYO key)" : "off / no key")}");
    Console.WriteLine($"  Config file     : {IntelSettings.ConfigPath}");
    return;
}

if (Idx("--hash") is var hi and >= 0 && hi + 1 < args.Length)
{
    using var intel = new ThreatIntel();
    var rep = await intel.LookupHashAsync(args[hi + 1]);
    PrintRep(rep);
    return;
}

if (Idx("--lookup") is var li and >= 0 && li + 1 < args.Length)
{
    using var intel = new ThreatIntel();
    Console.WriteLine($"Hashing {args[li + 1]} ...");
    var rep = await intel.LookupFileAsync(args[li + 1]);
    PrintRep(rep);
    return;
}

if (Idx("--scan-file") is var si and >= 0 && si + 1 < args.Length)
{
    using var intel = new ThreatIntel();
    if (!intel.CanScan) { Console.WriteLine("VirusTotal not configured — add your key in %LOCALAPPDATA%\\Sentinel\\settings.json"); return; }
    Console.WriteLine("Scanning via VirusTotal (this can take a moment) ...");
    PrintScan(await intel.ScanFileAsync(args[si + 1]));
    return;
}

if (Idx("--scan-url") is var ui and >= 0 && ui + 1 < args.Length)
{
    using var intel = new ThreatIntel();
    if (!intel.CanScan) { Console.WriteLine("VirusTotal not configured — add your key in %LOCALAPPDATA%\\Sentinel\\settings.json"); return; }
    Console.WriteLine("Submitting URL to VirusTotal ...");
    PrintScan(await intel.ScanUrlAsync(args[ui + 1]));
    return;
}

if (Idx("--check-ip") is var ipi and >= 0 && ipi + 1 < args.Length)
{
    using var intel = new ThreatIntel();
    PrintScan(await intel.CheckIpAsync(args[ipi + 1]));
    return;
}

if (Idx("--scan") is var sc and >= 0 && sc + 1 < args.Length)
{
    using var intel = new ThreatIntel();
    Console.WriteLine("Advanced scan (auto-detect IP / URL / file) ...");
    PrintScan(await intel.AdvancedScanAsync(args[sc + 1]));
    return;
}

static void PrintRep(HashReputation r)
{
    Console.WriteLine(new string('-', 40));
    Console.WriteLine($"  verdict : {r.Level}");
    Console.WriteLine($"  source  : {(string.IsNullOrEmpty(r.Source) ? "(none answered)" : r.Source)}");
    if (r.Detail is not null) Console.WriteLine($"  detail  : {r.Detail}");
    if (r.Family is not null) Console.WriteLine($"  family  : {r.Family}");
    if (r.Permalink is not null) Console.WriteLine($"  report  : {r.Permalink}");
}

static void PrintScan(ScanReport r)
{
    Console.WriteLine(new string('-', 40));
    if (!r.Ok) { Console.WriteLine($"  error: {r.Error}"); return; }
    Console.WriteLine($"  target  : {r.Target}");
    Console.WriteLine($"  verdict : {r.Level}  ({r.Malicious} malicious / {r.TotalEngines} engines)");
    if (r.Family is not null) Console.WriteLine($"  family  : {r.Family}");
    if (r.Permalink is not null) Console.WriteLine($"  report  : {r.Permalink}");
}

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
