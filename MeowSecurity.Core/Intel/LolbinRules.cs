using System;
using System.Collections.Generic;

namespace MeowSecurity.Core.Intel;

/// <summary>
/// Living-off-the-land heuristics — local, offline, zero-cost signals.
///
/// Modern intrusions rarely drop novel binaries; they abuse trusted, signed Windows
/// tools (LOLBins). CISA's 2025 guidance is to judge these by *how and why* they run,
/// not by file reputation. So a signed powershell.exe is fine — a signed powershell.exe
/// launched by winword.exe with an encoded command is not. This class supplies those
/// two judgements: is this a LOLBin, and does its command line look abusive.
/// </summary>
public static class LolbinRules
{
    /// <summary>Signed Windows binaries commonly abused for execution, download, or proxy execution.</summary>
    public static readonly IReadOnlySet<string> Lolbins = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe", "regsvcs.exe", "regasm.exe",
        "installutil.exe", "msbuild.exe", "certutil.exe", "certreq.exe",
        "bitsadmin.exe", "wmic.exe", "hh.exe", "msiexec.exe", "forfiles.exe",
        "schtasks.exe", "at.exe", "sc.exe", "odbcconf.exe", "cmstp.exe",
        "installutil.exe", "ieexec.exe", "presentationhost.exe", "msdt.exe",
    };

    /// <summary>Processes that spawning a shell/LOLBin from is a classic macro/exploit tell.</summary>
    public static readonly IReadOnlySet<string> SuspiciousParents = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe",
        "onenote.exe", "acrord32.exe", "acrobat.exe", "wscript.exe", "mshta.exe",
        "eqnedt32.exe", "visio.exe",
    };

    public static bool IsLolbin(string? imageName) =>
        !string.IsNullOrEmpty(imageName) && Lolbins.Contains(imageName);

    public static bool IsSuspiciousParent(string? parentImageName) =>
        !string.IsNullOrEmpty(parentImageName) && SuspiciousParents.Contains(parentImageName);

    /// <summary>
    /// Command-line tells that push a LOLBin from "normal admin use" toward "attack".
    /// Returns a short reason when something looks off, else null.
    ///
    /// Every rule here is deliberately narrower than the textbook version. Developer tooling
    /// runs PowerShell constantly — `-NoProfile -ExecutionPolicy Bypass`, `Invoke-Expression`
    /// of a local script, `curl` in a build step — and a monitor that flags all of it teaches
    /// its user to ignore it. So the download and IEX rules fire only in *combination*: the
    /// cradle pattern (fetch + execute), not either half alone.
    /// </summary>
    public static string? SuspiciousCommandLine(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return null;
        var cl = commandLine.ToLowerInvariant();

        bool fetches = cl.Contains("downloadstring") || cl.Contains("downloadfile") ||
                       cl.Contains("downloaddata") || cl.Contains("webclient") ||
                       cl.Contains("invoke-webrequest") || cl.Contains("iwr ") ||
                       cl.Contains("invoke-restmethod") || cl.Contains("irm ") ||
                       cl.Contains("bitstransfer");
        bool executes = cl.Contains("iex") || cl.Contains("invoke-expression") ||
                        cl.Contains("start-process") || cl.Contains("| . ") ||
                        cl.Contains("frombase64string");
        bool remote = cl.Contains("http://") || cl.Contains("https://") ||
                      cl.Contains("ftp://") || cl.Contains(@"\\");

        // PowerShell obfuscation: an encoded command hides what it does from the user *and*
        // from the event log, which is the whole reason attackers reach for it.
        if (HasEncodedCommand(cl))
            return "encoded PowerShell command";
        if (cl.Contains("-nop") && (cl.Contains("-w hidden") || cl.Contains("-windowstyle hidden")))
            return "hidden no-profile PowerShell";

        // The download cradle: fetch and run in one breath, never touching disk.
        if (fetches && executes)
            return "Invoke-Expression of downloaded code";
        if (fetches && remote)
            return "in-line remote download";

        // certutil / bitsadmin used as downloaders.
        if (cl.Contains("certutil") && (cl.Contains("-urlcache") || cl.Contains("-decode")))
            return "certutil used to download/decode";
        if (cl.Contains("bitsadmin") && cl.Contains("/transfer"))
            return "bitsadmin file transfer";

        // rundll32 / regsvr32 proxy execution of remote or odd payloads.
        if (cl.Contains("regsvr32") && (cl.Contains("/i:http") || cl.Contains("scrobj.dll")))
            return "regsvr32 remote scriptlet (squiblydoo)";
        if (cl.Contains("rundll32") && cl.Contains("javascript:"))
            return "rundll32 javascript payload";
        if (cl.Contains("mshta") && (cl.Contains("http") || cl.Contains("vbscript:") || cl.Contains("javascript:")))
            return "mshta remote/script payload";

        return null;
    }

    /// <summary>
    /// PowerShell accepts any unambiguous prefix of -EncodedCommand (-e, -en, -enc …), so a
    /// literal "-enc" test misses half the real samples. This walks the tokens instead and
    /// asks for the shape that matters: an -e* switch followed by a long base64 blob.
    /// </summary>
    private static bool HasEncodedCommand(string lowerCommandLine)
    {
        var parts = lowerCommandLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        for (int i = 0; i < parts.Length - 1; i++)
        {
            var t = parts[i];
            if (t.Length < 2 || (t[0] != '-' && t[0] != '/')) continue;
            if (!"encodedcommand".StartsWith(t[1..], StringComparison.Ordinal)) continue;

            var blob = parts[i + 1].Trim('"');
            if (blob.Length >= 20 && IsBase64(blob)) return true;
        }
        return lowerCommandLine.Contains("-encodedcommand");
    }

    /// <summary>
    /// Pulls the script back out of a -EncodedCommand.
    ///
    /// An encoded command is only alarming because it hides what it is about to do — so the
    /// useful response is not to flag the encoding, it is to undo it and read the thing. Plenty
    /// of honest tooling encodes its commands to dodge quoting rules; malware encodes to hide.
    /// Only the decoded text can tell those apart, and it is also what the user needs to see.
    ///
    /// PowerShell encodes as UTF-16LE base64.
    /// </summary>
    public static string? DecodeEncodedCommand(string? commandLine) =>
        DecodeEncodedCommand(commandLine, out _);

    /// <summary>
    /// Decodes a <c>-EncodedCommand</c> blob, and says whether it got all of it.
    ///
    /// The kernel's process-start event truncates long command lines, so a blob that arrives
    /// through the live capture is often cut mid-way and will not decode as valid Base64. That
    /// is our limitation, not the attacker's, and reporting it as "something is hidden here"
    /// puts a High alert on every long encoded command on the machine — including the ordinary
    /// tooling that encodes to escape quoting rules.
    ///
    /// So a cut blob is trimmed back to the last whole Base64 group and decoded anyway. What
    /// comes out is the beginning of the real script, which is worth judging on its own terms;
    /// <paramref name="complete"/> is false so the caller can be honest that it read a prefix
    /// rather than the whole thing.
    /// </summary>
    public static string? DecodeEncodedCommand(string? commandLine, out bool complete)
    {
        complete = true;
        if (string.IsNullOrWhiteSpace(commandLine)) return null;

        var parts = commandLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        for (int i = 0; i < parts.Length - 1; i++)
        {
            var t = parts[i];
            if (t.Length < 2 || (t[0] != '-' && t[0] != '/')) continue;
            if (!"encodedcommand".StartsWith(t[1..], StringComparison.OrdinalIgnoreCase)) continue;

            var blob = parts[i + 1].Trim('"');
            if (blob.Length < 20 || !IsBase64(blob.ToLowerInvariant())) continue;

            string? decoded = Decode(blob);
            if (decoded is not null) return decoded;

            // Not valid Base64 as it stands — almost always because the command line was cut
            // short before it reached us. Read as much as forms whole groups.
            int whole = blob.Length - (blob.Length % 4);
            if (whole >= 20 && Decode(blob[..whole]) is { } partial)
            {
                complete = false;
                return partial;
            }
            return null;
        }
        return null;
    }

    private static string? Decode(string blob)
    {
        try
        {
            var bytes = Convert.FromBase64String(blob);
            var text = System.Text.Encoding.Unicode.GetString(bytes);
            // A wrong guess at the encoding shows up as interleaved NULs.
            if (text.Contains('\0')) text = System.Text.Encoding.UTF8.GetString(bytes);
            text = text.Trim();

            // Valid Base64 is not the same as a script. A blob that decodes to control
            // characters decoded into nothing readable, and calling that "nothing suspicious
            // here" would be the opposite of the truth — we could not read it at all, which is
            // exactly what the caller needs to be told.
            return text.Any(c => !char.IsControl(c)) ? text : null;
        }
        catch (FormatException) { return null; }
    }

    private static bool IsBase64(string s)
    {
        foreach (var c in s)
            if (!char.IsAsciiLetterOrDigit(c) && c != '+' && c != '/' && c != '=') return false;
        return true;
    }
}
