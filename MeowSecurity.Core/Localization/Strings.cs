using System.Globalization;

namespace MeowSecurity.Core.Localization;

public enum AppLanguage
{
    Arabic,
    English,
}

/// <summary>
/// Every word the application says, in both languages it speaks.
///
/// The text lives in one table rather than scattered through the code, for a reason beyond
/// tidiness: a security tool's wording is part of its accuracy. "Suspicious" and "malicious"
/// are different claims, and when the same phrase appears in an alert, a log line and a
/// tooltip, they must agree. One table makes that checkable.
///
/// Keys are dotted and grouped by area. Lookups never throw: a missing key returns itself, so
/// a mistake shows up in the interface as a visible key instead of an empty label.
/// </summary>
public static class Strings
{
    private static AppLanguage _language = FromSystem();

    /// <summary>Raised when the language changes, so a window can rebuild itself.</summary>
    public static event Action? LanguageChanged;

    public static AppLanguage Language
    {
        get => _language;
        set
        {
            if (_language == value) return;
            _language = value;
            LanguageChanged?.Invoke();
        }
    }

    /// <summary>Arabic reads right to left; the interface mirrors with it.</summary>
    public static bool IsRightToLeft => _language == AppLanguage.Arabic;

    /// <summary>First run follows Windows: Arabic system, Arabic interface.</summary>
    private static AppLanguage FromSystem() =>
        CultureInfo.CurrentUICulture.TwoLetterISOLanguageName.Equals("ar", StringComparison.OrdinalIgnoreCase)
            ? AppLanguage.Arabic
            : AppLanguage.English;

    public static AppLanguage Parse(string? name) =>
        string.Equals(name, "en", StringComparison.OrdinalIgnoreCase) ? AppLanguage.English :
        string.Equals(name, "ar", StringComparison.OrdinalIgnoreCase) ? AppLanguage.Arabic :
        FromSystem();

    public static string Code => _language == AppLanguage.Arabic ? "ar" : "en";

    public static string T(string key) =>
        Table.TryGetValue(key, out var pair)
            ? (_language == AppLanguage.Arabic ? pair.Ar : pair.En)
            : key;

    public static string T(string key, params object?[] args)
    {
        try { return string.Format(T(key), args); }
        catch (FormatException) { return T(key); }
    }

    private static readonly Dictionary<string, (string Ar, string En)> Table = new()
    {
        // ---------------- shared vocabulary ----------------
        ["verdict.safe"] = ("آمن", "Safe"),
        ["verdict.review"] = ("راجعه", "Review"),
        ["verdict.suspicious"] = ("مشبوه", "Suspicious"),

        ["severity.critical"] = ("حرج", "Critical"),
        ["severity.high"] = ("مرتفع", "High"),
        ["severity.medium"] = ("متوسط", "Medium"),
        ["severity.low"] = ("منخفض", "Low"),
        ["severity.info"] = ("معلومة", "Info"),

        ["signature.signed"] = ("موقع", "Signed"),
        ["signature.invalid"] = ("غير صالح", "Invalid"),
        ["signature.unsigned"] = ("غير موقع", "Unsigned"),
        ["signature.unknown"] = ("—", "—"),

        ["common.yes"] = ("نعم", "Yes"),
        ["common.disabled"] = ("معطل", "Disabled"),
        ["common.system"] = ("النظام", "System"),
        ["common.none"] = ("لا شيء", "None"),
        ["common.cancel"] = ("إلغاء", "Cancel"),
        ["common.confirm"] = ("تأكيد", "Confirm"),

        // ---------------- units ----------------
        ["unit.bytes"] = ("ب", "B"),
        ["unit.kilo"] = ("ك", "K"),
        ["unit.mega"] = ("م", "M"),
        ["unit.giga"] = ("غ", "G"),
        ["unit.tera"] = ("ت", "T"),
        ["unit.rate.b"] = ("ب/ث", "B/s"),
        ["unit.rate.k"] = ("ك/ث", "K/s"),
        ["unit.rate.m"] = ("م/ث", "M/s"),
        ["unit.rate.g"] = ("غ/ث", "G/s"),
        ["unit.connections"] = ("{0} اتصال", "{0} connections"),
        ["unit.ports"] = ("{0} منفذ", "{0} ports"),
        ["unit.threads"] = ("خيط {0}", "{0} threads"),

        // ---------------- engine ----------------
        ["ctl.unsupported"] = ("نوع غير مدعوم", "Unsupported entry type"),
        ["ctl.no-entry"] = ("لا يمكن تحديد المدخل", "Cannot identify the entry"),
        ["ctl.no-key"] = ("تعذر فتح مفتاح السجل", "Could not open the registry key"),
        ["ctl.enabled"] = ("أعيد تفعيله", "Re-enabled"),
        ["ctl.disabled"] = ("عطل — لن يعمل عند الإقلاع", "Disabled — it will not run at startup"),
        ["ctl.needs-admin-machine"] = ("يحتاج صلاحية المدير لتعديل مدخل على مستوى الجهاز", "Changing a machine-wide entry needs administrator rights"),
        ["ctl.no-task"] = ("لا يمكن تحديد المهمة", "Cannot identify the task"),
        ["ctl.no-scheduler"] = ("خدمة جدولة المهام غير متاحة", "The Task Scheduler service is unavailable"),
        ["ctl.task-enabled"] = ("أعيد تفعيل المهمة", "Task re-enabled"),
        ["ctl.task-disabled"] = ("عطلت المهمة المجدولة", "Scheduled task disabled"),
        ["ctl.task-needs-admin"] = ("هذه المهمة تحتاج صلاحية المدير", "This task needs administrator rights"),
        ["ctl.no-service"] = ("لا يمكن تحديد الخدمة", "Cannot identify the service"),
        ["ctl.service-missing"] = ("الخدمة غير موجودة", "The service does not exist"),
        ["ctl.service-enabled"] = ("أعيد تفعيل الخدمة — تعمل بعد إعادة التشغيل", "Service re-enabled — it will start after a reboot"),
        ["ctl.service-disabled"] = ("عطلت الخدمة — تتوقف بعد إعادة التشغيل", "Service disabled — it stops after a reboot"),
        ["ctl.service-needs-admin"] = ("تعطيل خدمة يحتاج صلاحية المدير", "Disabling a service needs administrator rights"),
        ["ctl.removed-registry"] = ("حذف المدخل من السجل", "Entry deleted from the registry"),
        ["ctl.file-missing"] = ("الملف غير موجود", "The file does not exist"),
        ["ctl.removed-startup"] = ("حذف من مجلد بدء التشغيل", "Deleted from the Startup folder"),
        ["ctl.no-delete"] = ("الخدمات والمهام تعطل ولا تحذف", "Services and tasks are disabled, never deleted"),
        ["ctl.delete-needs-admin"] = ("الحذف يحتاج صلاحية المدير", "Deleting needs administrator rights"),
        ["autorun.user-startup"] = ("بدء تشغيل المستخدم", "User startup"),
        ["autorun.system-startup"] = ("بدء تشغيل النظام", "System startup"),
        ["autorun.driver"] = ("مشغل نظام", "Driver"),
        ["autorun.service"] = ("خدمة", "Service"),
        ["autorun.task"] = ("مهمة مجدولة", "Scheduled task"),
        ["autorun.no-target"] = ("تعذر تحديد الملف المستهدف", "Could not resolve the target file"),
        ["autorun.target-missing"] = ("الملف المستهدف غير موجود", "The target file no longer exists"),
        ["autorun.bad-signature"] = ("توقيع رقمي غير صالح", "Invalid digital signature"),
        ["autorun.unsigned-temp"] = ("غير موقع ويعمل من مجلد مؤقت", "Unsigned, and runs from a temporary folder"),
        ["autorun.unsigned-out"] = ("غير موقع خارج مجلدات النظام", "Unsigned, outside the system folders"),
        ["autorun.unsigned"] = ("غير موقع", "Unsigned"),
        ["autorun.signed"] = ("موقع", "Signed"),
        ["startup.no-exe"] = ("لم يعثر على ملف البرنامج", "The application file was not found"),
        ["startup.registered"] = ("سيعمل مع بدء ويندوز بصلاحية كاملة", "It will start with Windows, with full privileges"),
        ["startup.unregistered"] = ("لن يعمل مع بدء ويندوز", "It will no longer start with Windows"),
        ["startup.needs-admin"] = ("التسجيل يحتاج صلاحية المدير مرة واحدة", "Registering needs administrator rights, once"),
        ["startup.remove-admin"] = ("الإلغاء يحتاج صلاحية المدير", "Removing it needs administrator rights"),
        ["startup.description"] = ("يشغل Meow Security مع بدء ويندوز بصلاحية كاملة حتى تعمل المراقبة اللحظية.", "Starts Meow Security with Windows at full privilege so the live capture can run."),
        ["health.cpu.detail"] = (
            "المعالج فوق {0:0}% منذ أكثر من دقيقة",
            "The processor has been above {0:0}% for more than a minute"),
        ["health.memory.detail"] = (
            "استهلاك الذاكرة فوق {0:0}% منذ أكثر من دقيقة",
            "Memory use has been above {0:0}% for more than a minute"),
        ["health.consumer"] = ("، وأكثر عملية استهلاكا هي {0}.", ", and the heaviest process is {0}."),
        ["autorun.bad-command"] = ("سطر أوامر مريب — {0}", "Suspicious command line — {0}"),
        ["health.cpu.title"] = ("ضغط مستمر على المعالج", "Sustained processor load"),
        ["health.memory.title"] = ("الذاكرة شبه ممتلئة", "Memory almost full"),
        ["live.hidden"] = ("مخفية عن أحد مصدري تعداد العمليات", "Hidden from one of the two enumeration sources"),
        ["live.bad-signature"] = ("توقيع رقمي غير صالح", "Invalid digital signature"),
        ["live.unsigned-temp"] = ("غير موقعة وتعمل من مجلد مؤقت", "Unsigned, running from a temporary folder"),
        ["live.unsigned-out"] = ("غير موقعة خارج مجلدات النظام", "Unsigned, outside the system folders"),
        ["live.opaque"] = ("تعذر الفحص (شغل بصلاحية المدير)", "Could not inspect (run as administrator)"),
        ["live.implanted"] = ("وحدة PE تعمل من ذاكرة غير مدعومة — كود محقون على الأرجح", "A PE module running from unbacked memory — most likely injected code"),
        ["etw.needs-admin"] = ("التقاط الأحداث اللحظية يحتاج صلاحية المدير", "Live capture needs administrator rights"),
    };

    /// <summary>
    /// Adds a group of entries from another part of the code. Keeps this file from becoming a
    /// single unreadable wall while still ending up as one table at run time.
    /// </summary>
    public static void Register(IReadOnlyDictionary<string, (string Ar, string En)> entries)
    {
        foreach (var (key, value) in entries) Table[key] = value;
    }
}
