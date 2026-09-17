using MeowSecurity.Core.Localization;

namespace MeowSecurity.Core.Detect;

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
    /// <summary>Rules whose advice is worth acting on immediately.</summary>
    private static readonly HashSet<string> UrgentRules =
    [
        "stealth.hidden", "memory.implanted-pe", "masquerade.system-name",
        "masquerade.double-extension", "lolbin.office-parent", "lolbin.encoded-payload",
        "lolbin.bare-rundll32", "sign.invalid",
        "credentials.lsass-read", "memory.foreign-thread",
        "hijack.sideloaded-module", "privilege.elevated-unsigned", "c2.known-pipe",
    ];

    static Guidance() => Strings.Register(Text);

    public static Advice For(string rule) =>
        Strings.T($"advice.{rule}.means") is var means && means.StartsWith("advice.", StringComparison.Ordinal)
            ? new Advice(Strings.T("advice.fallback.means"), Strings.T("advice.fallback.do"), false)
            : new Advice(means, Strings.T($"advice.{rule}.do"), UrgentRules.Contains(rule));

    public static Advice For(SecurityEvent ev) => For(ev.Rule);

    private static readonly Dictionary<string, (string Ar, string En)> Text = new()
    {
        ["advice.stealth.hidden.means"] = (
            "عملية تخفي نفسها عن إحدى طرق تعداد العمليات في ويندوز.",
            "A process is hiding itself from one of the ways Windows lists running programs."),
        ["advice.stealth.hidden.do"] = (
            "هذا سلوك جذور خفية ولا يفعله برنامج عادي. افصل الجهاز عن الإنترنت، وافحصه ببرنامج حماية موثوق، ولا تدخل كلمات مرور قبل تنظيفه.",
            "This is rootkit behaviour and no ordinary program does it. Disconnect from the internet, scan with a trusted anti-malware tool, and do not type any passwords until the machine is clean."),

        ["advice.c2.known-pipe.means"] = (
            "قناة اتصال داخلية على الجهاز تحمل الاسم الافتراضي لاداة يستعملها المهاجمون.",
            "An internal communication channel on this machine carries the default name of a tool attackers use."),
        ["advice.c2.known-pipe.do"] = (
            "اذا لم تكن انت او فريق تقنية المعلومات عندك تجرون اختبار اختراق الان، عامل الجهاز كمخترق: افصله عن الشبكة، ولا تدخل كلمات مرور عليه، واطلب مساعدة مختص. فرق الامن تستعمل الادوات نفسها في اختباراتها المشروعة.",
            "Unless you or your IT team are running a penetration test right now, treat the machine as compromised: disconnect it from the network, do not type any passwords on it, and get expert help. Security teams use these same tools in legitimate tests."),

        ["advice.hijack.sideloaded-module.means"] = (
            "برنامج موثوق حمل مكتبة غير موقعة من مجلد يستطيع اي برنامج الكتابة فيه.",
            "A trusted program has loaded an unsigned library from a folder anything can write to."),
        ["advice.hijack.sideloaded-module.do"] = (
            "هذه طريقة شائعة لتشغيل كود داخل برنامج سليم دون لمسه. افتح مجلد المكتبة المذكورة وانظر متى وصلت. اذا لم تكن جزءا من برنامج ثبته بنفسك، انه العملية وافحص الجهاز.",
            "This is a common way to run code inside a healthy program without touching it. Open the folder the library is in and look at when it arrived. If it is not part of something you installed yourself, end the process and scan the machine."),

        ["advice.privilege.debug-enabled.means"] = (
            "برنامج يمسك الصلاحية التي تخوله فتح اي عملية اخرى على الجهاز.",
            "A program holds the privilege that lets it open any other process on the machine."),
        ["advice.privilege.debug-enabled.do"] = (
            "المصححات وادوات النسخ الاحتياطي تحتاجها فعلا، لكن برنامجا يعمل من مجلد مؤقت لا يحتاجها ابدا. اذا لم تعرف البرنامج فانهه.",
            "Debuggers and backup tools genuinely need it, but a program running from a temporary folder never does. If you do not recognise it, end it."),

        ["advice.privilege.impersonation.means"] = (
            "برنامج ينفذ عملا بهوية حساب اخر بدل هويته.",
            "A program is doing work under another account's identity instead of its own."),
        ["advice.privilege.impersonation.do"] = (
            "الخدمات وبرامج الشبكة تفعل هذا بشكل مشروع. راقبه: اذا ظهر مع اي تنبيه اخر عن البرنامج نفسه، عامل الاثنين معا كحادثة واحدة.",
            "Services and network software do this legitimately. Keep an eye on it: if it appears alongside any other alert about the same program, treat the two together as one incident."),

        ["advice.privilege.elevated-unsigned.means"] = (
            "ملف لا يحمل توقيعا رقميا يعمل بصلاحيات مدير من مجلد غير محمي.",
            "A file with no digital signature is running with administrator rights from an unprotected folder."),
        ["advice.privilege.elevated-unsigned.do"] = (
            "اذا لم تمنحه هذه الصلاحيات بنفسك للتو، فهذه نهاية عملية تصعيد صلاحيات. انهه، ثم راجع صفحة بدء التشغيل بحثا عن ما يعيده.",
            "If you did not just grant it those rights yourself, this is the end of a privilege escalation. End it, then check the startup page for whatever brings it back."),

        ["advice.credentials.lsass-read.means"] = (
            "برنامج يقرأ الذاكرة التي يحفظ فيها ويندوز كلمات مرور جلستك.",
            "A program is reading the memory where Windows keeps your session's passwords."),
        ["advice.credentials.lsass-read.do"] = (
            "أدوات الحماية وبعض أدوات المطورين تفعل هذا لأسباب مشروعة، فاقرأ اسم البرنامج أولا. إذا لم تعرفه: أنه العملية، ثم غير كلمات مرورك من جهاز آخر — لا من هذا الجهاز.",
            "Security software and some developer tools do this for legitimate reasons, so read the program's name first. If you do not recognise it: end the process, then change your passwords from a different device — not this one."),

        ["advice.inject.handles.means"] = (
            "برنامج يمسك صلاحية الكتابة داخل برامج أخرى وتشغيل كود فيها.",
            "A program holds the right to write inside other programs and run code there."),
        ["advice.inject.handles.do"] = (
            "المصححات وأدوات مكافحة الغش وبعض برامج الحماية تفعل هذا بشكل طبيعي. إذا كان البرنامج غير معروف أو يمسك عدة عمليات دفعة واحدة، أنهه وافحص الجهاز.",
            "Debuggers, anti-cheat and some security software do this normally. If the program is unfamiliar, or holds several processes at once, end it and scan the machine."),

        ["advice.memory.foreign-thread.means"] = (
            "كود يعمل داخل هذه العملية بلا ملف على القرص يقف خلفه.",
            "Code is running inside this process with no file on disk behind it."),
        ["advice.memory.foreign-thread.do"] = (
            "هذا هو شكل الكود المحقون. لكن الالعاب المحمية بانظمة مكافحة الغش، وبعض البرامج المضغوطة، تفك تشفير نفسها في الذاكرة بالطريقة نفسها — فاذا كانت العملية لعبة تعرفها فهي غالبا سليمة. اذا لم تعرف البرنامج: انهه وافحص الجهاز.",
            "This is what injected code looks like. But games with anti-cheat protection, and some packed programs, unpack themselves in memory the same way — so if the process is a game you recognise it is probably fine. If you do not recognise the program: end it and scan the machine."),

        ["advice.memory.implanted-pe.means"] = (
            "برنامج يعمل من داخل ذاكرة عملية أخرى بدل أن يعمل من ملف على القرص.",
            "Code is running inside another process's memory instead of from a file on disk."),
        ["advice.memory.implanted-pe.do"] = (
            "هذا حقن كود. أنه العملية من صفحة العمليات، ثم افحص الجهاز. إذا رجعت بعد إعادة التشغيل فالمصدر في بدء التشغيل — راجع تلك الصفحة.",
            "That is code injection. End the process from the Processes page, then scan the machine. If it comes back after a reboot the source is a startup entry — check that page."),

        ["advice.masquerade.system-name.means"] = (
            "ملف يحمل اسم أحد مكونات ويندوز لكنه يعمل من مكان غير مجلد ويندوز.",
            "A file carries the name of a Windows component but runs from somewhere other than the Windows folder."),
        ["advice.masquerade.system-name.do"] = (
            "النسخة الأصلية لا تعمل إلا من مجلد النظام، فهذا انتحال شبه مؤكد. أنه العملية، وافتح موقع الملف واحذفه، ثم تأكد من صفحة بدء التشغيل.",
            "The real one only ever runs from the system folder, so this is almost certainly an impostor. End the process, open its file location and delete it, then check the Startup page."),

        ["advice.masquerade.double-extension.means"] = (
            "الملف يظهر كمستند لكنه في الحقيقة برنامج تنفيذي.",
            "The file looks like a document but is actually a program."),
        ["advice.masquerade.double-extension.do"] = (
            "هذه حيلة مرفقات البريد. لا تفتحه مرة أخرى، وأنه العملية، واحذف الملف من موقعه.",
            "This is the classic email-attachment trick. Do not open it again, end the process, and delete the file."),

        ["advice.lolbin.office-parent.means"] = (
            "مستند أو سكربت شغل أداة نظام مثل PowerShell — وهذا ما تفعله الماكروهات الخبيثة.",
            "A document or script launched a system tool such as PowerShell — which is what a malicious macro does."),
        ["advice.lolbin.office-parent.do"] = (
            "إذا لم تكن قد فتحت مستندا للتو فأنه العملية فورا. وإذا فتحت مستندا وصلك بالبريد فاعتبره مصدر الإصابة ولا تفتحه ثانية.",
            "If you did not just open a document, end the process now. If you did open one that arrived by email, treat it as the source and do not open it again."),

        ["advice.lolbin.encoded-payload.means"] = (
            "أمر مخفي بترميز Base64، وبعد فك ترميزه ظهر أنه ينزل أو ينفذ كودا من الإنترنت.",
            "A command hidden with Base64 encoding which, once decoded, downloads or executes code from the internet."),
        ["advice.lolbin.encoded-payload.do"] = (
            "الإخفاء نفسه ليس له سبب مشروع هنا. أنه العملية، وانظر إلى الأمر المفكوك في التفاصيل لتعرف من أين يأتي.",
            "The hiding itself has no legitimate reason here. End the process, and read the decoded command in the details to see where it came from."),

        ["advice.lolbin.command-line.means"] = (
            "أداة نظام موثوقة تعمل بوسائط غير معتادة.",
            "A trusted system tool is running with unusual arguments."),
        ["advice.lolbin.command-line.do"] = (
            "إن كنت أنت من شغل الأمر فتجاهله. وإن لم تكن، فأنه العملية وافحص الملف الذي شغلها من صفحة التهديدات.",
            "If you ran the command yourself, ignore this. If you did not, end the process and look at whatever launched it on the Threats page."),

        ["advice.lolbin.bare-rundll32.means"] = (
            "rundll32 يعمل بلا أي مكتبة — لا وظيفة له بهذا الشكل.",
            "rundll32 is running with no library to load — in that form it has no purpose."),
        ["advice.lolbin.bare-rundll32.do"] = (
            "غالبا عملية فارغة استعملت لحقن كود. أنه العملية وراقب إن كانت ترجع.",
            "It is usually an empty process used as a host for injected code. End it and watch whether it returns."),

        ["advice.lolbin.user-path.means"] = (
            "نسخة من أداة نظام تعمل من مجلد يستطيع أي برنامج الكتابة فيه.",
            "A copy of a system tool is running from a folder any program can write to."),
        ["advice.lolbin.user-path.do"] = (
            "الأدوات الأصلية تعمل من مجلد ويندوز. افتح موقع الملف وتأكد من مصدره قبل أن تثق به.",
            "The genuine tools live in the Windows folder. Open the file's location and satisfy yourself where it came from before trusting it."),

        ["advice.script.user-path.means"] = (
            "مشغل سكربتات يعمل على ملف في مجلد قابل للكتابة.",
            "A script host is running something from a writable folder."),
        ["advice.script.user-path.do"] = (
            "إذا لم تكن تشغل سكربتا بنفسك فأنه العملية، وافتح موقع الملف لتعرف ما هو.",
            "If you are not running a script yourself, end the process and open the file location to see what it is."),

        ["advice.sign.invalid.means"] = (
            "الملف موقع رقميا لكن التوقيع مكسور — أي أنه عدل بعد توقيعه.",
            "The file is digitally signed but the signature is broken — meaning it was modified after signing."),
        ["advice.sign.invalid.do"] = (
            "لا تثق به. احذف البرنامج وأعد تنزيله من موقعه الرسمي مباشرة.",
            "Do not trust it. Remove the program and download it again from its official site."),

        ["advice.trust.unsigned-userland.means"] = (
            "برنامج بلا توقيع رقمي يعمل من مجلد مؤقت أو مجلد مستخدم.",
            "An unsigned program is running from a temporary or user folder."),
        ["advice.trust.unsigned-userland.do"] = (
            "كثير من البرامج الصغيرة والأدوات المجانية بلا توقيع، فهذا وحده ليس دليلا. افتح موقع الملف: إن كنت تعرفه فلا بأس، وإن لم تعرفه فأنه العملية.",
            "Plenty of small and free tools are unsigned, so this alone proves nothing. Open the file's location: if you recognise it, fine; if you do not, end the process."),

        ["advice.network.unsigned-remote.means"] = (
            "برنامج بلا توقيع يفتح اتصالات مع الإنترنت من مجلد قابل للكتابة.",
            "An unsigned program running from a writable folder is opening connections to the internet."),
        ["advice.network.unsigned-remote.do"] = (
            "افتح صفحة الشبكة وانظر كم يرسل وكم يستقبل. إن لم تكن تعرف البرنامج فأنه العملية.",
            "Open the Network page and see how much it is sending and receiving. If you do not recognise the program, end it."),

        ["advice.health.cpu.means"] = (
            "المعالج يعمل بأقصى طاقته منذ أكثر من دقيقة دون توقف.",
            "The processor has been at full load for over a minute without pause."),
        ["advice.health.cpu.do"] = (
            "إن كنت تشغل لعبة أو تحويل فيديو أو تحديثا فهذا طبيعي. وإن لم تكن تفعل شيئا ثقيلا فافتح صفحة العمليات وانظر إلى أعلى عملية استهلاكا — التعدين الخفي يبدو هكذا بالضبط.",
            "If you are running a game, a video export or an update, this is normal. If you are not doing anything heavy, open the Processes page and look at the top consumer — hidden mining looks exactly like this."),

        ["advice.health.memory.means"] = (
            "الذاكرة شبه ممتلئة، ولهذا يبطؤ الجهاز.",
            "Memory is nearly full, which is why the machine feels slow."),
        ["advice.health.memory.do"] = (
            "أغلق ما لا تحتاجه، وابدأ بأعلى عملية في صفحة العمليات. إذا كانت عملية واحدة تلتهم الذاكرة وحدها ولا تعرفها فأنهها.",
            "Close what you do not need, starting with the top process on the Processes page. If a single process you do not recognise is eating it all, end it."),

        ["advice.fallback.means"] = (
            "سلوك غير معتاد من هذه العملية.",
            "Unusual behaviour from this process."),
        ["advice.fallback.do"] = (
            "افتح صفحة الأحداث لقراءة التفاصيل، وإذا لم تكن تعرف البرنامج فافتح موقع الملف.",
            "Open the Events page for the details, and if you do not recognise the program, open its file location."),
    };
}
