using System.Security.Principal;
using System.Text;
using Sentinel.Core.Intel;
using Sentinel.Core.Persistence;
using Sentinel.Core.Processes;

Console.OutputEncoding = Encoding.UTF8;

if (args.Contains("--autoruns"))
{
    var ar = new AutorunScanner().Scan();
    Console.WriteLine($"Autoruns — {ar.Count} entries\n" + new string('-', 78));
    foreach (var e in ar.OrderByDescending(x => (int)x.Verdict))
        Console.WriteLine($"  [{e.Verdict,-10}] {e.Location,-16} {e.Name,-28} {e.Reason}\n" +
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
Emit($"Sentinel — process scan  ({(elevated ? "elevated" : "NOT elevated — some processes will be opaque")})");
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
