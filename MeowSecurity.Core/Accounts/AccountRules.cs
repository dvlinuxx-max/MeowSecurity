using MeowSecurity.Core.Detect;
using MeowSecurity.Core.Localization;

namespace MeowSecurity.Core.Accounts;

/// <summary>
/// Judges who can sign in to this machine.
///
/// The rules here are unusual for this product in one way: elsewhere a finding describes
/// something happening, and here it describes something that is simply *true* and probably
/// should not be. An extra local administrator is not an event — nobody is running it, it
/// generates no processes and no network traffic — but it is the most durable foothold there
/// is, and it will still be there after every process has been killed and every startup entry
/// cleaned.
///
/// That makes the baseline the hard part. A machine can legitimately have two administrators,
/// and telling a user their own second account is suspicious would be worse than useless. So
/// these rules describe what is *unusual about Windows' own defaults* — the Guest account
/// switched back on, an account that has never once signed in yet holds administrator rights —
/// rather than pretending to know which of the owner's accounts belong to them.
/// </summary>
public static class AccountRules
{
    static AccountRules() => Strings.Register(Text);

    /// <summary>Findings about the machine's accounts and the people signed in to it.</summary>
    public static IReadOnlyList<Detection> Evaluate(
        IReadOnlyList<LocalAccount> accounts, IReadOnlyList<LogonSession> sessions)
    {
        var found = new List<Detection>();

        // The Guest account ships disabled on every version of Windows and has for twenty
        // years. Somebody turned it on, and it is the classic quiet way back in: an account
        // nobody watches, usually without a password.
        var guest = accounts.FirstOrDefault(a => a.IsBuiltIn && a.IsEnabled &&
            !a.Name.Equals(Environment.UserName, StringComparison.OrdinalIgnoreCase) &&
            a.LastLogon is null && !a.IsAdministrator);
        if (guest is not null)
            found.Add(new Detection("account.builtin-enabled", Severity.Medium, 30,
                Strings.T("account.guest.title", guest.Name),
                Strings.T("account.guest.detail"), "T1078.001"));

        // An administrator account that has never been signed into is the shape of one created
        // by something other than the person who owns the machine. A real second account gets
        // used; one made to be waiting is not.
        foreach (var a in accounts.Where(a =>
                     a.IsAdministrator && a.IsEnabled && a.LastLogon is null && !a.IsBuiltIn))
            found.Add(new Detection("account.unused-admin", Severity.High, 50,
                Strings.T("account.newadmin.title", a.Name),
                Strings.T("account.newadmin.detail"), "T1136.001"));

        // Somebody signed in over the network, on a machine whose owner believes they are alone
        // at it. Ordinary in an office and alarming on a home machine, so it is reported as a
        // fact to check rather than as an attack.
        foreach (var s in sessions.Where(s =>
                     s.ClientAddress is not null && s.User.Length > 0 &&
                     s.State is "active" or "connected"))
            found.Add(new Detection("account.remote-session", Severity.High, 45,
                Strings.T("account.remote.title", s.User),
                Strings.T("account.remote.detail", s.ClientAddress!), "T1021.001"));

        return found;
    }

    private static readonly Dictionary<string, (string Ar, string En)> Text = new()
    {
        ["account.guest.title"] = ("حساب ويندوز المدمج مفعل: {0}", "A built-in Windows account is enabled: {0}"),
        ["account.guest.detail"] = (
            "هذا الحساب يأتي معطلا مع ويندوز دائما. تفعيله يفتح بابا لا يراقبه أحد، وغالبا بلا كلمة مرور.",
            "This account ships disabled with Windows, always. Enabling it opens a door nobody watches, usually with no password."),

        ["account.newadmin.title"] = ("حساب مدير لم يستخدم قط: {0}", "An administrator account that has never signed in: {0}"),
        ["account.newadmin.detail"] = (
            "حساب بصلاحيات مدير كاملة ولم يسجل دخوله ولا مرة. الحساب الحقيقي يستعمل؛ الحساب المصنوع للانتظار لا يستعمل.",
            "An account with full administrator rights that has never once signed in. A real account gets used; one made to wait does not."),

        ["account.remote.title"] = ("جلسة دخول عن بعد: {0}", "A remote sign-in session: {0}"),
        ["account.remote.detail"] = ("متصل من {0}.", "Connected from {0}."),
    };
}
