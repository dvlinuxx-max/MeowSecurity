# Store listing copy

Ready to paste into Partner Center once a package has been uploaded — the listing languages
are read from the package, so the page stays empty until then.

Store policy 10.7 expects a listing's language to be one the app speaks. This one speaks
Arabic and English, so both listings are here and neither is a translation of a marketing
pitch: each says the same true things in its own language.

There is one rule for all of this text. **Never call it an antivirus.** It is a monitor and an
analyser, it does not remove malware, and it is not a replacement for Microsoft Defender.
Saying otherwise would be a policy problem and, worse, would leave somebody less protected
than they thought.

---

## English

### Description

Most monitors tell you *what* is running. This one is built around *why*.

Modern intrusions rarely drop a new program. They drive the trusted, signed Windows tools
already on the machine, and a clean file check proves very little. What gives them away is
context: who started a program, from where, and with what instructions.

Meow Security watches for that, and it runs entirely offline. It has no accounts, no keys, no
telemetry and no servers. It sends nothing, anywhere.

**What it looks for**

- **Credential theft.** Every cross-process handle on the machine is resolved. A handle that
  can read the memory where Windows keeps your session's passwords is how credentials are
  stolen, whatever the tool is called and whoever signed it.
- **Injected code.** Executable memory with no file behind it, program headers implanted in
  another process, and threads whose entry point lies outside every loaded file.
- **Library hijacking.** A signed program that has loaded an unsigned library from a folder
  anything could write to.
- **Behavioural detection.** Rules score each program on its parent, its command line, where
  it runs from and what it is pretending to be, and tag findings with MITRE ATT&CK ids. An
  encoded PowerShell command is decoded and judged by what it actually contains.
- **Live capture from the kernel.** Programs are judged the moment they start, so a command
  that runs and exits in a third of a second is not missed.
- **Per-process network use.** Windows keeps no such counter — even Task Manager's network
  column is machine-wide. This one adds up the kernel's own events, so you can see which
  program is uploading.
- **Hidden processes**, found by listing them two independent ways and comparing.
- **Startup control.** Run keys, Startup folders, services, drivers, scheduled tasks and WMI
  subscriptions — the last of which appears in none of the other four. Each can be opened,
  switched off or removed, and switching one off writes the same setting Task Manager uses, so
  it can be undone from either side.
- **Accounts and sessions.** Who can sign in, who is an administrator, and who is signed in
  now — including where a remote session is coming from.

**Plain-language alerts.** Every finding says what it means and what to do about it, in two
sentences, with the buttons to do it.

Arabic and English, light and dark, and the layout mirrors with the language.

**Not an antivirus.** Meow Security is a monitor and an analyser. It does not remove malware
and it is not a replacement for Microsoft Defender or any antivirus.

Free and open source under the GNU General Public License v3.0.
Source: https://github.com/dvlinuxx-max/MeowSecurity

### Short description

An offline process, memory and network monitor for Windows that detects intrusions by
behaviour rather than by file checks. Not an antivirus.

### Search terms

process monitor, host intrusion detection, memory analysis, autoruns, MITRE ATT&CK,
credential theft, code injection, offline security, task manager

---

## العربية

### الوصف

أغلب المراقبات تكَولك **شنو** يشتغل. هذا مبني على **ليش**.

الاختراقات الحديثة نادراً تنزّل برنامجاً جديداً. تشغّل أدوات ويندوز الموثوقة والموقّعة الموجودة
أصلاً بالجهاز، وفحص الملف النظيف ما يثبت شي تقريباً. الي يفضحها هو السياق: منو شغّل البرنامج،
ومن وين، وبأي أوامر.

Meow Security يراقب هذا، ويشتغل **دون اتصال بالكامل**. لا حسابات، لا مفاتيح، لا تتبّع، ولا خوادم.
ما يرسل أي شي، لأي جهة.

**شنو يدوّر عليه**

- **سرقة بيانات الدخول.** يحلّ كل مقبض عابر للعمليات بالجهاز. المقبض الي يخوّل قراءة الذاكرة الي
  يحفظ بيها ويندوز كلمات مرور جلستك هو طريقة السرقة نفسها — مهما كان اسم الأداة ومهما كان موقّعها.
- **الكود المحقون.** ذاكرة قابلة للتنفيذ بلا ملف وراها، ترويسات برامج مزروعة داخل عملية أخرى،
  وخيوط نقطة بدايتها خارج كل ملف محمّل.
- **اختطاف المكتبات.** برنامج موقّع حمّل مكتبة غير موقّعة من مجلد يكدر أي شي يكتب بيه.
- **كشف سلوكي.** قواعد تعطي كل برنامج درجة حسب أصله وسطر أوامره ومن وين يشتغل وشنو ينتحل،
  وتربط النتائج بمعرّفات MITRE ATT&CK. وأمر PowerShell المرمّز **يُفكّ** ويُحكم عليه بمحتواه الفعلي.
- **التقاط حيّ من الكيرنل.** البرامج تُحكم لحظة تشغيلها، فأمر يشتغل وينتهي بثلث ثانية ما يفوت.
- **استهلاك الشبكة لكل عملية.** ويندوز ما عنده هذا العدّاد أصلاً — حتى عمود الشبكة بمدير المهام
  يعطي مجموع الجهاز. هذا يجمع أحداث الكيرنل نفسها، فتشوف أي برنامج يرفع بيانات.
- **العمليات المخفية**، تُكتشف بتعدادها بطريقتين مستقلتين ومقارنتهما.
- **التحكم ببدء التشغيل.** مفاتيح Run، ومجلدات بدء التشغيل، والخدمات، والتعريفات، والمهام المجدولة،
  واشتراكات WMI — وهذا الأخير ما يظهر بأي وحدة من الأربعة الي كبله. كل عنصر ينفتح أو ينطفي أو
  ينحذف، والإطفاء يكتب نفس الإعداد الي يستعمله مدير المهام، فينراجع من الجهتين.
- **الحسابات والجلسات.** منو يكدر يسجّل دخول، ومنو مدير، ومنو داخل هسه — وين موقع الجلسة البعيدة.

**إنذارات بلغة مفهومة.** كل نتيجة تكَولك شنو تعني وشنو تسوي، بجملتين، مع الأزرار الي تسويها.

عربي وإنجليزي، فاتح وداكن، والتخطيط ينعكس مع اللغة.

**ليس مضاد فيروسات.** Meow Security مراقب ومحلّل. لا يزيل البرمجيات الخبيثة، وليس بديلاً عن
Microsoft Defender ولا عن أي مضاد فيروسات.

مجاني ومفتوح المصدر برخصة GNU GPL v3.0.
المصدر: https://github.com/dvlinuxx-max/MeowSecurity

### الوصف المختصر

مراقب عمليات وذاكرة وشبكة لويندوز يعمل دون اتصال، ويكشف الاختراق بالسلوك لا بفحص الملفات.
ليس مضاد فيروسات.

### كلمات البحث

مراقب العمليات, كشف الاختراق, تحليل الذاكرة, بدء التشغيل, حقن الكود, سرقة كلمات المرور,
أمان بدون إنترنت, مدير المهام

---

## Screenshots

At least one is required, 1366×768 or larger. The pages worth showing, in order:

1. **Overview** — the shield gauge and the machine's state at a glance.
2. **Processes** — the live table with verdicts and per-process network.
3. **Threats** — a finding with its plain-language advice, which is the product's whole point.
4. **Autoruns** — the five kinds of persistence, with the controls.
5. **Accounts** — who can sign in and who is signed in.

Capture them in **English** for the English listing and **Arabic** for the Arabic one; the
interface follows the system language, so switch it in Settings between captures.

One caution: these are screenshots of a real machine. Before uploading any of them, look at
what is actually in the process list and the paths — a personal folder name, a document title
in a window caption, or a colleague's machine name in a session row are all things that are
easy to publish by accident and impossible to unpublish.
