using System;
using System.Collections.Generic;

namespace Sentinel.Core.Intel;

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
    /// </summary>
    public static string? SuspiciousCommandLine(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return null;
        var cl = commandLine.ToLowerInvariant();

        // PowerShell obfuscation / download-cradle markers.
        if (cl.Contains("-enc") || cl.Contains("-encodedcommand") || cl.Contains("frombase64string"))
            return "encoded PowerShell command";
        if (cl.Contains("-nop") && cl.Contains("-w hidden"))
            return "hidden no-profile PowerShell";
        if (cl.Contains("downloadstring") || cl.Contains("downloadfile") || cl.Contains("invoke-webrequest") || cl.Contains("iwr ") || cl.Contains("wget ") || cl.Contains("curl "))
            return "in-line remote download";
        if (cl.Contains("iex(") || cl.Contains("invoke-expression"))
            return "Invoke-Expression of downloaded code";

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
}
