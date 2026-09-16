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

        // ---------------- rows and cards ----------------
        ["event.tipheader"] = ("{0} {1}  ·  نقاط الخطورة {2}", "{0} {1}  ·  severity score {2}"),
        ["alert.where"] = ("{0} (رقم {1})", "{0} (pid {1})"),
        ["alert.where.path"] = ("{0} (رقم {1})  —  {2}", "{0} (pid {1})  —  {2}"),


        ["crash.startup"] = (
            "تعذر بدء Meow Security.\n\n{0}: {1}\n\nالتفاصيل في:\n{2}",
            "Meow Security could not start.\n\n{0}: {1}\n\nDetails in:\n{2}"),
        ["crash.running"] = (
            "حدث خطأ غير متوقع، والمراقبة مستمرة.\n\n{0}: {1}\n\nالتفاصيل في:\n{2}",
            "Something went wrong, and monitoring is continuing.\n\n{0}: {1}\n\nDetails in:\n{2}"),

        // ---------------- interface ----------------
        ["settings.english"] = ("English interface", "English interface"),
        ["alert.suspicious"] = ("عملية مشبوهة: {0}", "Suspicious process: {0}"),
        ["alert.suspicious.body"] = ("ظهرت عملية مشبوهة.", "A suspicious process appeared."),
        ["common.alert"] = ("تنبيه", "Alert"),
        ["common.error"] = ("خطأ", "Error"),
        ["confirm.clear-log"] = ("حذف كل الأحداث المسجلة نهائيا؟", "Permanently delete every recorded event?"),
        ["confirm.kill.system"] = (
            "إنهاء {0} (PID {1})؟\n\nإنهاء عملية نظام قد يجعل الجهاز غير مستقر حتى إعادة التشغيل.",
            "End {0} (pid {1})?\n\nEnding a system process can leave the machine unstable until a reboot."),
        ["confirm.remove.entry"] = (
            "حذف {0} نهائيا من بدء التشغيل؟\n\n{1}\n\n",
            "Permanently remove {0} from startup?\n\n{1}\n\n"),
        ["hero.clean"] = ("جهازك سليم", "Your machine is clean"),
        ["hero.clean-review"] = ("جهازك سليم، مع عناصر للمراجعة", "Your machine is clean, with items to review"),
        ["hero.clean.sub"] = ("كل العمليات موقعة، ولا كود محقون، ولا عملية مخفية", "Every process is signed, no injected code, nothing hidden"),
        ["summary.all-clear"] = ("كلها سليمة", "all clear"),

        ["about.version"] = ("الإصدار {0}.{1}  ·  رخصة GPL-3.0", "Version {0}.{1}  ·  GPL-3.0"),
        ["confirm.delete.title"] = ("تأكيد الحذف", "Confirm deletion"),
        ["confirm.kill.body"] = ("إنهاء {0} (رقم {1})؟\n\n", "End {0} (pid {1})?\n\n"),
        ["confirm.kill.title"] = ("تأكيد الإنهاء", "Confirm"),
        ["elev.full"] = ("يعمل بصلاحية المدير — رؤية كاملة لكل العمليات", "Running as administrator — full visibility"),
        ["elev.limited"] = ("بعض عمليات النظام مخفية بدون صلاحية المدير", "Some system processes are hidden without administrator rights"),
        ["etw.off"] = ("الالتقاط اللحظي متوقف — يحتاج صلاحية المدير. بدونه قد تفوت عمليات تعيش أقل من ثانية.", "Live capture is off — it needs administrator rights. Without it, processes that live under a second can be missed."),
        ["etw.on"] = ("الالتقاط اللحظي يعمل — يفحص كل عملية لحظة إنشائها", "Live capture is running — every process is judged the moment it is created"),
        ["etw.unavailable"] = ("الالتقاط اللحظي غير متاح: {0}", "Live capture unavailable: {0}"),
        ["hero.alarm"] = ("انتبه — {0} عنصر يحتاج تدقيقا", "Attention — {0} items need checking"),
        ["hero.review"] = ("افتح صفحة التهديدات لمراجعة العناصر الحمراء", "Open the Threats page to review the red items"),
        ["hero.review-count"] = ("{0} عنصر بلا توقيع خارج مجلدات النظام — غالبا عادي", "{0} unsigned items outside the system folders — usually normal"),
        ["msg.already-gone"] = ("العملية انتهت بالفعل.", "The process has already exited."),
        ["msg.elevate-now"] = ("{0}\n\nتشغيل البرنامج بصلاحية المدير الآن؟", "{0}\n\nRun the app as administrator now?"),
        ["msg.entry-only"] = ("الملف نفسه لا يحذف — يحذف المدخل الذي يشغله فقط.", "The file itself is not deleted — only the entry that launches it."),
        ["msg.file-gone"] = ("الملف لم يعد موجودا في مساره.", "The file is no longer at that path."),
        ["msg.kill-error"] = ("تعذر الإنهاء: {0}", "Could not end it: {0}"),
        ["msg.kill-failed"] = ("تعذر إنهاء العملية: {0}\n\nجرب تشغيل البرنامج بصلاحية المدير.", "Could not end the process: {0}\n\nTry running the app as administrator."),
        ["msg.kill-warning"] = ("إذا كان البرنامج يحفظ شيئا الآن فقد تفقده.", "If the program is saving something right now, you may lose it."),
        ["msg.killed"] = ("أنهيت {0}", "Ended {0}"),
        ["msg.no-delete"] = ("الخدمات والمهام المجدولة تعطل ولا تحذف — التعطيل قابل للتراجع والحذف لا.", "Services and scheduled tasks are disabled, never deleted — disabling can be undone, deleting cannot."),
        ["msg.path-gone"] = ("الملف والمجلد غير موجودين — المدخل يشير إلى مسار محذوف.", "Neither the file nor its folder exists — the entry points at a deleted path."),
        ["msg.suspend-failed"] = ("تعذر الإيقاف — قد تكون عملية محمية.", "Could not suspend it — it may be a protected process."),
        ["startup.off"] = ("بدونه تتوقف المراقبة عند إعادة تشغيل الجهاز حتى تفتح البرنامج بنفسك", "Without it, monitoring stops at the next reboot until you open the app yourself"),
        ["startup.on"] = ("مسجل كمهمة تعمل بصلاحية كاملة عند تسجيل الدخول", "Registered as a task that runs with full privileges at sign-in"),
        ["summary.alerts"] = ("{0} تنبيه · {1} يحتاج تصرفا", "{0} alerts · {1} need action"),
        ["summary.autoruns"] = ("{0} عنصر", "{0} entries"),
        ["summary.events"] = ("{0} حدث · {1} خطير", "{0} events · {1} serious"),
        ["summary.flagged"] = ("{0} يحتاج مراجعة", "{0} need review"),
        ["summary.hidden"] = ("{0} من مكونات ويندوز مخفية", "{0} Windows components hidden"),
        ["summary.no-alerts"] = ("لا تنبيهات", "No alerts"),
        ["summary.no-events"] = ("لا أحداث", "No events"),
        ["tray.exit"] = ("خروج", "Exit"),
        ["tray.open"] = ("فتح Meow Security", "Open Meow Security"),
        ["tray.pause"] = ("إيقاف المراقبة مؤقتا", "Pause monitoring"),
        ["tray.resume"] = ("استئناف المراقبة", "Resume monitoring"),
        ["tray.still.body"] = ("المراقبة تعمل في الخلفية. انقر الأيقونة للعودة، أو أوقفها من قائمة اليمين.", "Monitoring continues in the background. Click the icon to come back, or stop it from the right-click menu."),
        ["tray.still.title"] = ("Meow Security ما زال يراقب", "Meow Security is still watching"),
        ["tray.tip.off"] = ("Meow Security — المراقبة متوقفة", "Meow Security — paused"),
        ["tray.tip.on"] = ("Meow Security — المراقبة تعمل", "Meow Security — monitoring"),

        ["net.title"] = ("حركة الشبكة", "Network traffic"),
        ["net.subtitle"] = ("عبر كل الواجهات النشطة", "Across every active interface"),
        ["empty.attention"] = ("لا شيء يحتاج انتباهك الآن — كل العمليات موقعة ولا كود محقون.", "Nothing needs your attention — every process is signed and no injected code."),

        ["about.author"] = ("تطوير: محمد عبد الرحمن", "Built by Mohammed Abd Alrahman"),
        ["about.disclaimer"] = ("أداة مراقبة وتحليل، ليست بديلا عن مضاد الفيروسات.", "A monitor and analyser — not a replacement for antivirus."),
        ["about.licence"] = ("نص الرخصة", "Licence text"),
        ["about.licence.body"] = ("برنامج حر مفتوح المصدر برخصة GNU GPL الإصدار 3. لك حرية استخدامه ودراسته وتعديله؛ وأي نسخة توزعها يجب أن تبقى مفتوحة المصدر بالرخصة نفسها.", "Free and open-source software under the GNU GPL version 3. You may use, study and modify it; any copy you distribute must stay open source under the same licence."),
        ["about.tagline"] = ("مراقب عمليات وذاكرة وشبكة، وكاشف اختراق للمضيف.", "A process, memory and network monitor, and a host intrusion detector."),
        ["alert.whattodo"] = ("ماذا تفعل", "What to do"),
        ["btn.clear-log"] = ("مسح السجل", "Clear the log"),
        ["btn.copyname"] = ("نسخ الاسم", "Copy name"),
        ["btn.disable"] = ("تعطيل", "Disable"),
        ["btn.dismiss"] = ("إخفاء", "Dismiss"),
        ["btn.elevate"] = ("تشغيل بصلاحية المدير", "Run as administrator"),
        ["btn.kill"] = ("إنهاء العملية", "End process"),
        ["btn.locate"] = ("فتح موقع الملف", "Open file location"),
        ["btn.locate.short"] = ("فتح الموقع", "Open location"),
        ["btn.mark-read"] = ("تعليم الكل كمقروء", "Mark all as read"),
        ["btn.pause"] = ("إيقاف مؤقت", "Pause"),
        ["btn.remove"] = ("إزالة", "Remove"),
        ["btn.resume"] = ("استئناف", "Resume"),
        ["btn.review"] = ("مراجعة", "Review"),
        ["btn.scan"] = ("فحص", "Scan"),
        ["btn.serious-only"] = ("الخطير فقط", "Serious only"),
        ["btn.show-system"] = ("إظهار عناصر النظام", "Show Windows components"),
        ["col.connections"] = ("الاتصالات", "Connections"),
        ["col.cpu"] = ("المعالج", "CPU"),
        ["col.details"] = ("التفاصيل", "Details"),
        ["col.down"] = ("تنزيل", "Down"),
        ["col.enabled"] = ("يعمل", "Enabled"),
        ["col.event"] = ("الحدث", "Event"),
        ["col.io"] = ("إدخال/إخراج", "I/O"),
        ["col.location"] = ("الموقع", "Location"),
        ["col.name"] = ("الاسم", "Name"),
        ["col.parent"] = ("الأب", "Parent"),
        ["col.path"] = ("المسار", "Path"),
        ["col.process"] = ("العملية", "Process"),
        ["col.publisher"] = ("الناشر", "Publisher"),
        ["col.reason"] = ("السبب", "Reason"),
        ["col.severity"] = ("الخطورة", "Severity"),
        ["col.signature"] = ("التوقيع", "Signature"),
        ["col.status"] = ("الحالة", "Status"),
        ["col.technique"] = ("التقنية", "Technique"),
        ["col.threads"] = ("خيوط", "Threads"),
        ["col.time"] = ("الوقت", "Time"),
        ["col.up"] = ("رفع", "Up"),
        ["empty.alerts"] = ("لا تنبيهات تحتاج انتباهك. كل ما يرصد يسجل في صفحة الأحداث.", "Nothing needs your attention. Everything observed is recorded on the Events page."),
        ["empty.events"] = ("لا أحداث بعد. يسجل هنا كل سلوك مريب لحظة وقوعه، ويبقى بعد إغلاق البرنامج.", "No events yet. Anything suspicious is recorded here as it happens, and stays after the app closes."),
        ["empty.threats"] = ("لا تهديدات. كل العمليات موقعة، ولا كود محقون، ولا عملية مخفية.", "No threats. Every process is signed, no injected code, nothing hidden."),
        ["hint.autoruns"] = ("اضغط فحص لعرض كل ما يبدأ تلقائيا مع النظام. اختر مدخلا لتعطيله أو فتح موقعه.", "Press Scan to list everything that starts by itself. Select an entry to disable it or open its location."),
        ["hint.search"] = ("ابحث باسم العملية أو رقمها…", "Search by process name or id…"),
        ["menu.disable-startup"] = ("تعطيل من بدء التشغيل", "Disable at startup"),
        ["menu.remove-entry"] = ("إزالة المدخل نهائيا", "Remove the entry permanently"),
        ["nav.alerts"] = ("التنبيهات", "Alerts"),
        ["nav.events"] = ("الأحداث", "Events"),
        ["nav.network"] = ("الشبكة", "Network"),
        ["nav.overview"] = ("نظرة عامة", "Overview"),
        ["nav.processes"] = ("العمليات", "Processes"),
        ["nav.settings"] = ("الإعدادات", "Settings"),
        ["nav.startup"] = ("بدء التشغيل", "Startup"),
        ["nav.threats"] = ("التهديدات", "Threats"),
        ["overview.attention"] = ("يحتاج انتباهك", "Needs your attention"),
        ["overview.memory"] = ("الذاكرة", "Memory"),
        ["overview.processes"] = ("العمليات النشطة", "Active processes"),
        ["overview.score"] = ("نقطة الحماية", "Protection score"),
        ["overview.starting"] = ("جاري بدء المراقبة…", "Starting the monitor…"),
        ["overview.status"] = ("حالة الحماية", "Protection status"),
        ["overview.subtitle"] = ("نفحص العمليات وتواقيعها وذاكرتها واتصالاتها", "Checking processes, their signatures, memory and connections"),
        ["page.events.title"] = ("سجل الأحداث", "Event log"),
        ["page.processes.title"] = ("العمليات الحية", "Live processes"),
        ["page.threats.title"] = ("التهديدات والعناصر المشبوهة", "Threats and suspicious items"),
        ["settings.about"] = ("عن البرنامج", "About"),
        ["settings.appearance"] = ("المظهر والسلوك", "Appearance and behaviour"),
        ["settings.background"] = ("الاستمرار بالمراقبة في الخلفية عند الإغلاق", "Keep monitoring in the background when closed"),
        ["settings.health"] = ("مراقبة حالة الجهاز (المعالج والذاكرة)", "Watch device health (processor and memory)"),
        ["settings.light"] = ("الوضع الفاتح", "Light theme"),
        ["settings.notify"] = ("الإشعارات عند ظهور عملية مشبوهة", "Notify when a suspicious process appears"),
        ["settings.sound"] = ("صوت مع التنبيه", "Play a sound with alerts"),
        ["settings.startup"] = ("التشغيل مع بدء ويندوز", "Start with Windows"),
        ["settings.system-notify"] = ("إشعارات ويندوز خارج البرنامج", "Windows notifications outside the app"),
        ["status.monitoring"] = ("المراقبة نشطة", "Monitoring"),

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
