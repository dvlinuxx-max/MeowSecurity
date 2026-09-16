using MeowSecurity.Core.Intel;
using MeowSecurity.Core.Localization;
using MeowSecurity.Core.Processes;

namespace MeowSecurity.Core.Detect;

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
                Strings.T("detect.hidden.title"),
                Strings.T("detect.hidden.detail"), "T1014"));

        if (ctx.HasImplantedPe)
            found.Add(new Detection("memory.implanted-pe", Severity.Critical, 75,
                Strings.T("detect.implanted.title"),
                Strings.T("detect.implanted.detail"), "T1055"));

        if (ctx.Signature == SignatureState.SignedInvalid)
            found.Add(new Detection("sign.invalid", Severity.High, 45,
                Strings.T("detect.badsign.title"),
                Strings.T("detect.badsign.detail"), "T1553"));

        // ---- masquerading: the right name in the wrong place ----

        if (path is not null && SystemImages.Contains(ctx.Name) &&
            !path.StartsWith(WinDir, StringComparison.Ordinal))
            found.Add(new Detection("masquerade.system-name", Severity.Critical, 70,
                Strings.T("detect.masquerade.title", ctx.Name),
                Strings.T("detect.masquerade.detail", ctx.ImagePath), "T1036.005"));

        if (HasDoubleExtension(ctx.Name))
            found.Add(new Detection("masquerade.double-extension", Severity.High, 40,
                Strings.T("detect.doubleext.title", ctx.Name),
                Strings.T("detect.doubleext.detail"), "T1036.007"));

        // ---- living off the land: trusted tools used in untrusted ways ----

        if (lolbin && LolbinRules.IsSuspiciousParent(ctx.ParentName))
            found.Add(new Detection("lolbin.office-parent", Severity.Critical, 70,
                Strings.T("detect.officeparent.title", ctx.ParentName, ctx.Name),
                Strings.T("detect.officeparent.detail"), "T1566.001"));

        var cmdTell = LolbinRules.SuspiciousCommandLine(ctx.CommandLine);
        if (cmdTell == "encoded PowerShell command")
            found.AddRange(JudgeEncodedCommand(ctx));
        else if (cmdTell is not null)
        {
            var (weight, severity, key) = Tells.TryGetValue(cmdTell, out var t)
                ? t : (50, Severity.High, cmdTell);
            string tellText = Strings.T(key);
            found.Add(new Detection("lolbin.command-line", severity, weight,
                Strings.T("detect.cmdline.title", ctx.Name), tellText, "T1059"));
        }

        if (lolbin && fromUserLand)
            found.Add(new Detection("lolbin.user-path", Severity.Medium, 25,
                Strings.T("detect.lolbinpath.title", ctx.Name),
                Strings.T("detect.lolbinpath.detail", ctx.ImagePath), "T1036"));

        if (ScriptHosts.Contains(ctx.Name) && fromUserLand)
            found.Add(new Detection("script.user-path", Severity.Medium, 30,
                Strings.T("detect.scriptpath.title", ctx.Name),
                Strings.T("detect.scriptpath.detail"), "T1059.005"));

        if (ctx.Name.Equals("rundll32.exe", StringComparison.OrdinalIgnoreCase) &&
            string.IsNullOrWhiteSpace(StripImage(ctx.CommandLine)))
            found.Add(new Detection("lolbin.bare-rundll32", Severity.High, 40,
                Strings.T("detect.rundll32.title"),
                Strings.T("detect.rundll32.detail"), "T1055.012"));

        // ---- location and trust ----

        if (ctx.Signature == SignatureState.Unsigned && fromUserLand)
            found.Add(new Detection("trust.unsigned-userland", Severity.Medium, 30,
                Strings.T("detect.unsigned.title", ctx.Name),
                Strings.T("detect.unsigned.detail", ctx.ImagePath), "T1204"));

        if (ctx.Signature == SignatureState.Unsigned && ctx.RemoteConnections > 0 && fromUserLand)
            found.Add(new Detection("network.unsigned-remote", Severity.High, 40,
                Strings.T("detect.unsignednet.title", ctx.Name),
                Strings.T("detect.unsignednet.detail", ctx.RemoteConnections), "T1071"));

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
                Strings.T("detect.cmdline.title", ctx.Name),
                Strings.T("detect.encoded.undecodable"), "T1059.001")];

        var inner = LolbinRules.SuspiciousCommandLine(script);
        if (inner is not null && inner != "encoded PowerShell command")
        {
            var (weight, _, key) = Tells.TryGetValue(inner, out var t) ? t : (50, Severity.High, inner);
            string tellText = Strings.T(key);
            // Hiding an attack is worse than running one in the open, so the encoding adds to it.
            return [new Detection("lolbin.encoded-payload", Severity.Critical, Math.Min(90, weight + 25),
                Strings.T("detect.encoded.hiding", ctx.Name),
                Strings.T("detect.encoded.decoded", tellText, Excerpt(script)), "T1027")];
        }

        return [new Detection("lolbin.command-line", Severity.Low, 10,
            Strings.T("detect.encoded.ordinary.title", ctx.Name),
            Strings.T("detect.encoded.ordinary.detail", Excerpt(script)), "T1059.001")];
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
    private static readonly Dictionary<string, (int Score, Severity Severity, string Key)> Tells = new()
    {
        ["encoded PowerShell command"] = (50, Severity.High, "tell.encoded"),
        ["hidden no-profile PowerShell"] = (45, Severity.High, "tell.hidden-window"),
        ["Invoke-Expression of downloaded code"] = (55, Severity.High, "tell.iex-download"),
        ["certutil used to download/decode"] = (50, Severity.High, "tell.certutil"),
        ["bitsadmin file transfer"] = (45, Severity.High, "tell.bitsadmin"),
        ["regsvr32 remote scriptlet (squiblydoo)"] = (60, Severity.High, "tell.squiblydoo"),
        ["rundll32 javascript payload"] = (55, Severity.High, "tell.rundll32-js"),
        ["mshta remote/script payload"] = (55, Severity.High, "tell.mshta"),

        // Common enough in honest work that it only earns a line in the log.
        ["in-line remote download"] = (10, Severity.Low, "tell.download"),
    };

    static BehaviorEngine() => Strings.Register(Text);

    private static readonly Dictionary<string, (string Ar, string En)> Text = new()
    {
        ["detect.hidden.title"] = ("عملية مخفية عن التعداد", "Process hidden from enumeration"),
        ["detect.hidden.detail"] = (
            "ظهرت في مصدر تعداد واحد فقط — سلوك جذور خفية (rootkit).",
            "Visible to only one of two enumeration sources — rootkit behaviour."),

        ["detect.implanted.title"] = ("كود محقون في الذاكرة", "Injected code in memory"),
        ["detect.implanted.detail"] = (
            "وحدة PE تعمل من ذاكرة غير مدعومة بملف على القرص.",
            "A PE module is running from memory with no file behind it."),

        ["detect.badsign.title"] = ("توقيع رقمي غير صالح", "Invalid digital signature"),
        ["detect.badsign.detail"] = (
            "الملف موقع لكن التوقيع مكسور — عدل بعد التوقيع أو انتحل ناشرا.",
            "Signed but the signature is broken — modified after signing, or impersonating a publisher."),

        ["detect.masquerade.title"] = ("اسم نظام من مسار غريب: {0}", "System name from an unexpected path: {0}"),
        ["detect.masquerade.detail"] = (
            "صورة نظام تعمل من {0} بدلا من مجلد ويندوز.",
            "A system image running from {0} instead of the Windows folder."),

        ["detect.doubleext.title"] = ("امتداد مزدوج: {0}", "Double extension: {0}"),
        ["detect.doubleext.detail"] = (
            "الاسم يظهر امتداد مستند بينما الملف تنفيذي.",
            "The name shows a document extension while the file is an executable."),

        ["detect.officeparent.title"] = ("{0} شغل {1}", "{0} launched {1}"),
        ["detect.officeparent.detail"] = (
            "مستند أو سكربت أطلق أداة نظام — النمط الكلاسيكي لماكرو خبيث.",
            "A document or script launched a system tool — the classic malicious-macro pattern."),

        ["detect.cmdline.title"] = ("سطر أوامر مريب: {0}", "Suspicious command line: {0}"),

        ["detect.lolbinpath.title"] = ("أداة نظام من مجلد المستخدم: {0}", "System tool from a user folder: {0}"),
        ["detect.lolbinpath.detail"] = (
            "نسخة من أداة النظام تعمل من {0}.",
            "A copy of the system tool running from {0}."),

        ["detect.scriptpath.title"] = ("مشغل سكربتات من مجلد المستخدم: {0}", "Script host from a user folder: {0}"),
        ["detect.scriptpath.detail"] = (
            "مضيف سكربت يعمل على محتوى من مجلد قابل للكتابة.",
            "A script host running content from a writable folder."),

        ["detect.rundll32.title"] = ("rundll32 بلا وسائط", "rundll32 with no arguments"),
        ["detect.rundll32.detail"] = (
            "rundll32 بلا DLL — غالبا هدف حقن أو عملية مفرغة.",
            "rundll32 with no DLL — usually an injection host or a hollowed process."),

        ["detect.unsigned.title"] = ("غير موقعة من مجلد قابل للكتابة: {0}", "Unsigned, from a writable folder: {0}"),
        ["detect.unsigned.detail"] = (
            "تعمل من {0} بلا توقيع رقمي.",
            "Running from {0} with no digital signature."),

        ["detect.unsignednet.title"] = ("اتصال خارجي من ملف غير موقع: {0}", "Unsigned file talking to the internet: {0}"),
        ["detect.unsignednet.detail"] = ("{0} اتصال خارجي نشط.", "{0} active outbound connections."),

        ["detect.encoded.undecodable"] = (
            "أمر PowerShell مرمز تعذر فك ترميزه.",
            "An encoded PowerShell command that could not be decoded."),
        ["detect.encoded.hiding"] = (
            "أمر مرمز يخفي سلوكا خطيرا: {0}",
            "Encoded command hiding dangerous behaviour: {0}"),
        ["detect.encoded.decoded"] = (
            "{0} — الأمر بعد فك الترميز: {1}",
            "{0} — decoded command: {1}"),
        ["detect.encoded.ordinary.title"] = ("أمر PowerShell مرمز: {0}", "Encoded PowerShell command: {0}"),
        ["detect.encoded.ordinary.detail"] = (
            "فك الترميز ولا يحتوي سلوكا مريبا: {0}",
            "Decoded, and contains nothing suspicious: {0}"),

        // Command-line tells, shared by the plain and the encoded paths.
        ["tell.encoded"] = (
            "أمر PowerShell مرمز بـ Base64 لإخفاء محتواه.",
            "A PowerShell command Base64-encoded to hide what it does."),
        ["tell.hidden-window"] = (
            "PowerShell بنافذة مخفية وبلا ملف تعريف.",
            "PowerShell with a hidden window and no profile."),
        ["tell.iex-download"] = (
            "تنفيذ كود منزل مباشرة في الذاكرة دون لمس القرص.",
            "Downloaded code executed straight in memory, never touching disk."),
        ["tell.certutil"] = (
            "certutil مستخدمة للتنزيل أو فك الترميز.",
            "certutil used to download or decode."),
        ["tell.bitsadmin"] = (
            "bitsadmin ينقل ملفا — قناة تنزيل خفية.",
            "bitsadmin transferring a file — a quiet download channel."),
        ["tell.squiblydoo"] = (
            "regsvr32 ينفذ سكربتا بعيدا (squiblydoo).",
            "regsvr32 executing a remote scriptlet (squiblydoo)."),
        ["tell.rundll32-js"] = ("rundll32 ينفذ حمولة JavaScript.", "rundll32 executing a JavaScript payload."),
        ["tell.mshta"] = ("mshta ينفذ حمولة بعيدة أو سكربتا.", "mshta executing a remote or script payload."),
        ["tell.download"] = (
            "تنزيل ملف من الإنترنت داخل سطر الأوامر.",
            "A file downloaded from the internet inside the command line."),
    };

}
