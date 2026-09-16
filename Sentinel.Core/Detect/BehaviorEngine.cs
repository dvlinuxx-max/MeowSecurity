using Sentinel.Core.Intel;
using Sentinel.Core.Processes;

namespace Sentinel.Core.Detect;

/// <summary>Everything the engine needs to judge one process, gathered by the caller.</summary>
public sealed record ProcessContext(
    int Pid,
    string Name,
    int ParentPid,
    string? ParentName,
    string? ImagePath,
    string? CommandLine,
    SignatureState Signature,
    bool IsHidden,
    bool HasImplantedPe,
    int RemoteConnections,
    int SessionId);

/// <summary>The engine's opinion of one process: the findings plus their combined weight.</summary>
public sealed record BehaviorResult(
    ProcessContext Context,
    IReadOnlyList<Detection> Detections,
    int Score)
{
    public Severity Severity => Score switch
    {
        >= 70 => Severity.Critical,
        >= 40 => Severity.High,
        >= 20 => Severity.Medium,
        > 0 => Severity.Low,
        _ => Severity.Info,
    };

    public bool IsEmpty => Detections.Count == 0;
}

/// <summary>
/// The behavioural half of the detection story.
///
/// Reputation answers "have we seen this file before"; this answers "does what it is doing
/// make sense". Intrusions today mostly run trusted, signed Microsoft binaries, so a clean
/// hash proves very little. What gives them away is context: who launched it, from where,
/// and with what arguments. Every rule here is local, offline and costs nothing, and each
/// one alone is only a hint — the caller sums the weights, because it is the *chain* that
/// convicts (winword → powershell → encoded command), not any single link.
///
/// Rules stay conservative on purpose. A monitor that cries wolf gets ignored, and then it
/// protects nobody.
/// </summary>
public static class BehaviorEngine
{
    private static readonly string WinDir =
        Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLowerInvariant();

    /// <summary>Images Windows itself owns. Seeing one of these outside System32 is a giveaway.</summary>
    private static readonly HashSet<string> SystemImages = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost.exe", "lsass.exe", "csrss.exe", "smss.exe", "wininit.exe", "winlogon.exe",
        "services.exe", "spoolsv.exe", "explorer.exe", "taskhostw.exe", "dwm.exe",
        "conhost.exe", "sihost.exe", "ctfmon.exe", "runtimebroker.exe", "searchindexer.exe",
    };

    /// <summary>Folders any user (or any malware running as that user) can write to.</summary>
    private static readonly string[] UserWritable =
    {
        @"\appdata\local\temp\", @"\appdata\roaming\", @"\windows\temp\",
        @"\downloads\", @"\$recycle.bin\", @"\programdata\", @"\public\",
    };

    /// <summary>Script hosts — legitimate, but a favourite first stage.</summary>
    private static readonly HashSet<string> ScriptHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "wscript.exe", "cscript.exe", "mshta.exe",
    };

    public static BehaviorResult Evaluate(ProcessContext ctx)
    {
        var found = new List<Detection>();
        string? path = ctx.ImagePath?.ToLowerInvariant();
        bool lolbin = LolbinRules.IsLolbin(ctx.Name);
        bool fromUserLand = path is not null && UserWritable.Any(path.Contains);

        // ---- direct evidence: the loudest signals we have ----

        if (ctx.IsHidden)
            found.Add(new Detection("stealth.hidden", Severity.Critical, 80,
                "عملية مخفية عن التعداد",
                "ظهرت في مصدر تعداد واحد فقط — سلوك جذور خفية (rootkit).", "T1014"));

        if (ctx.HasImplantedPe)
            found.Add(new Detection("memory.implanted-pe", Severity.Critical, 75,
                "كود محقون في الذاكرة",
                "وحدة PE تعمل من ذاكرة غير مدعومة بملف على القرص.", "T1055"));

        if (ctx.Signature == SignatureState.SignedInvalid)
            found.Add(new Detection("sign.invalid", Severity.High, 45,
                "توقيع رقمي غير صالح",
                "الملف موقع لكن التوقيع مكسور — عدل بعد التوقيع أو انتحل ناشرا.", "T1553"));

        // ---- masquerading: the right name in the wrong place ----

        if (path is not null && SystemImages.Contains(ctx.Name) &&
            !path.StartsWith(WinDir, StringComparison.Ordinal))
            found.Add(new Detection("masquerade.system-name", Severity.Critical, 70,
                $"اسم نظام من مسار غريب: {ctx.Name}",
                $"صورة نظام تعمل من {ctx.ImagePath} بدلا من مجلد ويندوز.", "T1036.005"));

        if (HasDoubleExtension(ctx.Name))
            found.Add(new Detection("masquerade.double-extension", Severity.High, 40,
                $"امتداد مزدوج: {ctx.Name}",
                "الاسم يظهر امتداد مستند بينما الملف تنفيذي.", "T1036.007"));

        // ---- living off the land: trusted tools used in untrusted ways ----

        if (lolbin && LolbinRules.IsSuspiciousParent(ctx.ParentName))
            found.Add(new Detection("lolbin.office-parent", Severity.Critical, 70,
                $"{ctx.ParentName} شغل {ctx.Name}",
                "مستند أو سكربت أطلق أداة نظام — النمط الكلاسيكي لماكرو خبيث.", "T1566.001"));

        var cmdTell = LolbinRules.SuspiciousCommandLine(ctx.CommandLine);
        if (cmdTell == "encoded PowerShell command")
            found.AddRange(JudgeEncodedCommand(ctx));
        else if (cmdTell is not null)
        {
            var (weight, severity, arabic) = Tells.TryGetValue(cmdTell, out var t)
                ? t : (50, Severity.High, cmdTell);
            found.Add(new Detection("lolbin.command-line", severity, weight,
                $"سطر أوامر مريب: {ctx.Name}", arabic, "T1059"));
        }

        if (lolbin && fromUserLand)
            found.Add(new Detection("lolbin.user-path", Severity.Medium, 25,
                $"أداة نظام من مجلد المستخدم: {ctx.Name}",
                $"نسخة من أداة النظام تعمل من {ctx.ImagePath}.", "T1036"));

        if (ScriptHosts.Contains(ctx.Name) && fromUserLand)
            found.Add(new Detection("script.user-path", Severity.Medium, 30,
                $"مشغل سكربتات من مجلد المستخدم: {ctx.Name}",
                "مضيف سكربت يعمل على محتوى من مجلد قابل للكتابة.", "T1059.005"));

        if (ctx.Name.Equals("rundll32.exe", StringComparison.OrdinalIgnoreCase) &&
            string.IsNullOrWhiteSpace(StripImage(ctx.CommandLine)))
            found.Add(new Detection("lolbin.bare-rundll32", Severity.High, 40,
                "rundll32 بلا وسائط",
                "rundll32 بلا DLL — غالبا هدف حقن أو عملية مفرغة.", "T1055.012"));

        // ---- location and trust ----

        if (ctx.Signature == SignatureState.Unsigned && fromUserLand)
            found.Add(new Detection("trust.unsigned-userland", Severity.Medium, 30,
                $"غير موقعة من مجلد قابل للكتابة: {ctx.Name}",
                $"تعمل من {ctx.ImagePath} بلا توقيع رقمي.", "T1204"));

        if (ctx.Signature == SignatureState.Unsigned && ctx.RemoteConnections > 0 && fromUserLand)
            found.Add(new Detection("network.unsigned-remote", Severity.High, 40,
                $"اتصال خارجي من ملف غير موقع: {ctx.Name}",
                $"{ctx.RemoteConnections} اتصال خارجي نشط.", "T1071"));

        int score = Math.Min(100, found.Sum(d => d.Score));
        return new BehaviorResult(ctx, found, score);
    }

    /// <summary>
    /// Decides what an encoded PowerShell command is actually worth.
    ///
    /// Encoding is a hiding technique, so the honest response is to stop guessing and read the
    /// script. Three outcomes: the decoded text is itself an attack (worse than the encoding
    /// ever was, and now we can say exactly why), the decoded text is ordinary (plenty of real
    /// tooling encodes to escape quoting rules — logged, never alarmed), or it will not decode
    /// at all, which leaves us where we started: something is hidden and we cannot see it.
    /// </summary>
    private static IEnumerable<Detection> JudgeEncodedCommand(ProcessContext ctx)
    {
        string? script = LolbinRules.DecodeEncodedCommand(ctx.CommandLine);

        if (script is null)
            return [new Detection("lolbin.command-line", Severity.High, 50,
                $"سطر أوامر مريب: {ctx.Name}",
                "أمر PowerShell مرمز تعذر فك ترميزه.", "T1059.001")];

        var inner = LolbinRules.SuspiciousCommandLine(script);
        if (inner is not null && inner != "encoded PowerShell command")
        {
            var (weight, _, arabic) = Tells.TryGetValue(inner, out var t) ? t : (50, Severity.High, inner);
            // Hiding an attack is worse than running one in the open, so the encoding adds to it.
            return [new Detection("lolbin.encoded-payload", Severity.Critical, Math.Min(90, weight + 25),
                $"أمر مرمز يخفي سلوكا خطيرا: {ctx.Name}",
                $"{arabic} — الأمر بعد فك الترميز: {Excerpt(script)}", "T1027")];
        }

        return [new Detection("lolbin.command-line", Severity.Low, 10,
            $"أمر PowerShell مرمز: {ctx.Name}",
            $"فك الترميز ولا يحتوي سلوكا مريبا: {Excerpt(script)}", "T1059.001")];
    }

    private static string Excerpt(string script)
    {
        var flat = script.ReplaceLineEndings(" ").Trim();
        while (flat.Contains("  ")) flat = flat.Replace("  ", " ");
        return flat.Length <= 160 ? flat : flat[..160] + "…";
    }

    /// <summary>"report.pdf.exe" — the extension the user sees is not the one Windows runs.</summary>
    private static bool HasDoubleExtension(string name)
    {
        string[] lures = { ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".png", ".ppt" };
        var lower = name.ToLowerInvariant();
        if (!lower.EndsWith(".exe") && !lower.EndsWith(".scr") && !lower.EndsWith(".com")) return false;
        var stem = lower[..lower.LastIndexOf('.')];
        return lures.Any(stem.EndsWith);
    }

    /// <summary>Drops the image path from a command line, leaving only the arguments.</summary>
    private static string? StripImage(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return null;
        var cl = commandLine.Trim();
        if (cl.StartsWith('"'))
        {
            int close = cl.IndexOf('"', 1);
            return close < 0 ? null : cl[(close + 1)..].Trim();
        }
        int space = cl.IndexOf(' ');
        return space < 0 ? null : cl[(space + 1)..].Trim();
    }

    /// <summary>
    /// Weight and wording per command-line tell. LolbinRules speaks English (it mirrors the
    /// public technique names) and the UI is Arabic, so the translation lives here with the
    /// score — the two belong together.
    ///
    /// Not every tell deserves the same volume. Downloading a file from PowerShell is worth
    /// writing down but is also what half of all install instructions on the internet say to
    /// do, so it stays under the alert floor: recorded, never a pop-up. Hiding what you are
    /// about to run is a different matter.
    /// </summary>
    private static readonly Dictionary<string, (int Score, Severity Severity, string Arabic)> Tells = new()
    {
        ["encoded PowerShell command"] =
            (50, Severity.High, "أمر PowerShell مرمز بـ Base64 لإخفاء محتواه."),
        ["hidden no-profile PowerShell"] =
            (45, Severity.High, "PowerShell بنافذة مخفية وبلا ملف تعريف."),
        ["Invoke-Expression of downloaded code"] =
            (55, Severity.High, "تنفيذ كود منزل مباشرة في الذاكرة دون لمس القرص."),
        ["certutil used to download/decode"] =
            (50, Severity.High, "certutil مستخدمة للتنزيل أو فك الترميز."),
        ["bitsadmin file transfer"] =
            (45, Severity.High, "bitsadmin ينقل ملفا — قناة تنزيل خفية."),
        ["regsvr32 remote scriptlet (squiblydoo)"] =
            (60, Severity.High, "regsvr32 ينفذ سكربتا بعيدا (squiblydoo)."),
        ["rundll32 javascript payload"] =
            (55, Severity.High, "rundll32 ينفذ حمولة JavaScript."),
        ["mshta remote/script payload"] =
            (55, Severity.High, "mshta ينفذ حمولة بعيدة أو سكربتا."),

        // Common enough in honest work that it only earns a line in the log.
        ["in-line remote download"] =
            (10, Severity.Low, "تنزيل ملف من الإنترنت داخل سطر الأوامر."),
    };
}
