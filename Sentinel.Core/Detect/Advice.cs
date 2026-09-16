namespace Sentinel.Core.Detect;

/// <summary>What a finding means, and what the person in front of the screen should do.</summary>
/// <param name="Means">The finding in plain language, no jargon, no technique ids.</param>
/// <param name="Do">The next action, concrete enough to actually carry out.</param>
/// <param name="Urgent">True when waiting is the wrong choice.</param>
public sealed record Advice(string Means, string Do, bool Urgent);

/// <summary>
/// The bridge between a detection and a decision.
///
/// A rule id and an ATT&amp;CK number tell a professional plenty and tell everyone else
/// nothing. Someone who opens this app because their machine "feels wrong" needs two
/// sentences: what was found, and what to do about it. Without that, an alert is just an
/// unpleasant feeling with a timestamp — and an alert nobody can act on trains people to
/// dismiss the next one.
///
/// Advice stays honest: where a finding is genuinely ambiguous it says so, rather than
/// pushing someone to kill a process that may well be their own software.
/// </summary>
public static class Guidance
{
    private static readonly Dictionary<string, Advice> ByRule = new()
    {
        ["stealth.hidden"] = new(
            "عملية تخفي نفسها عن إحدى طرق تعداد العمليات في ويندوز.",
            "هذا سلوك جذور خفية ولا يفعله برنامج عادي. افصل الجهاز عن الإنترنت، وافحصه ببرنامج حماية موثوق، ولا تدخل كلمات مرور قبل تنظيفه.",
            Urgent: true),

        ["memory.implanted-pe"] = new(
            "برنامج يعمل من داخل ذاكرة عملية أخرى بدل أن يعمل من ملف على القرص.",
            "هذا حقن كود. أنه العملية من صفحة العمليات، ثم افحص الجهاز. إذا رجعت بعد إعادة التشغيل فالمصدر في بدء التشغيل — راجع تلك الصفحة.",
            Urgent: true),

        ["masquerade.system-name"] = new(
            "ملف يحمل اسم أحد مكونات ويندوز لكنه يعمل من مكان غير مجلد ويندوز.",
            "النسخة الأصلية لا تعمل إلا من مجلد النظام، فهذا انتحال شبه مؤكد. أنه العملية، وافتح موقع الملف واحذفه، ثم تأكد من صفحة بدء التشغيل.",
            Urgent: true),

        ["masquerade.double-extension"] = new(
            "الملف يظهر كمستند لكنه في الحقيقة برنامج تنفيذي.",
            "هذه حيلة مرفقات البريد. لا تفتحه مرة أخرى، وأنه العملية، واحذف الملف من موقعه.",
            Urgent: true),

        ["lolbin.office-parent"] = new(
            "مستند أو سكربت شغل أداة نظام مثل PowerShell — وهذا ما تفعله الماكروهات الخبيثة.",
            "إذا لم تكن قد فتحت مستندا للتو فأنه العملية فورا. وإذا فتحت مستندا وصلك بالبريد فاعتبره مصدر الإصابة ولا تفتحه ثانية.",
            Urgent: true),

        ["lolbin.encoded-payload"] = new(
            "أمر مخفي بترميز Base64، وبعد فك ترميزه ظهر أنه ينزل أو ينفذ كودا من الإنترنت.",
            "الإخفاء نفسه ليس له سبب مشروع هنا. أنه العملية، وانظر إلى الأمر المفكوك في التفاصيل لتعرف من أين يأتي.",
            Urgent: true),

        ["lolbin.command-line"] = new(
            "أداة نظام موثوقة تعمل بوسائط غير معتادة.",
            "إن كنت أنت من شغل الأمر فتجاهله. وإن لم تكن، فأنه العملية وافحص الملف الذي شغلها من صفحة التهديدات.",
            Urgent: false),

        ["lolbin.bare-rundll32"] = new(
            "rundll32 يعمل بلا أي مكتبة — لا وظيفة له بهذا الشكل.",
            "غالبا عملية فارغة استعملت لحقن كود. أنه العملية وراقب إن كانت ترجع.",
            Urgent: true),

        ["lolbin.user-path"] = new(
            "نسخة من أداة نظام تعمل من مجلد يستطيع أي برنامج الكتابة فيه.",
            "الأدوات الأصلية تعمل من مجلد ويندوز. افتح موقع الملف وافحصه بالفحص المتقدم قبل أن تثق به.",
            Urgent: false),

        ["script.user-path"] = new(
            "مشغل سكربتات يعمل على ملف في مجلد قابل للكتابة.",
            "إذا لم تكن تشغل سكربتا بنفسك فأنه العملية، وافحص الملف من صفحة التهديدات.",
            Urgent: false),

        ["sign.invalid"] = new(
            "الملف موقع رقميا لكن التوقيع مكسور — أي أنه عدل بعد توقيعه.",
            "لا تثق به. احذف البرنامج وأعد تنزيله من موقعه الرسمي مباشرة.",
            Urgent: true),

        ["trust.unsigned-userland"] = new(
            "برنامج بلا توقيع رقمي يعمل من مجلد مؤقت أو مجلد مستخدم.",
            "كثير من البرامج الصغيرة والأدوات المجانية بلا توقيع، فهذا وحده ليس دليلا. افتح موقع الملف: إن كنت تعرفه فلا بأس، وإن لم تعرفه فافحصه بالفحص المتقدم.",
            Urgent: false),

        ["network.unsigned-remote"] = new(
            "برنامج بلا توقيع يفتح اتصالات مع الإنترنت من مجلد قابل للكتابة.",
            "افتح صفحة الشبكة وانظر إلى أين يتصل. إن كان المكان غير مألوف فأنه العملية وافحص الملف.",
            Urgent: false),

        ["health.cpu"] = new(
            "المعالج يعمل بأقصى طاقته منذ أكثر من دقيقة دون توقف.",
            "إن كنت تشغل لعبة أو تحويل فيديو أو تحديثا فهذا طبيعي. وإن لم تكن تفعل شيئا ثقيلا فافتح صفحة العمليات وانظر إلى أعلى عملية استهلاكا — التعدين الخفي يبدو هكذا بالضبط.",
            Urgent: false),

        ["health.memory"] = new(
            "الذاكرة شبه ممتلئة، ولهذا يبطؤ الجهاز.",
            "أغلق ما لا تحتاجه، وابدأ بأعلى عملية في صفحة العمليات. إذا كانت عملية واحدة تلتهم الذاكرة وحدها ولا تعرفها فافحصها.",
            Urgent: false),
    };

    private static readonly Advice Fallback = new(
        "سلوك غير معتاد من هذه العملية.",
        "افتح صفحة الأحداث لقراءة التفاصيل، وإذا لم تكن تعرف البرنامج فافحصه بالفحص المتقدم.",
        Urgent: false);

    public static Advice For(string rule) => ByRule.TryGetValue(rule, out var a) ? a : Fallback;

    public static Advice For(SecurityEvent ev) => For(ev.Rule);
}
