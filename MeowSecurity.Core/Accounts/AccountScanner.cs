using System.Runtime.InteropServices;

namespace MeowSecurity.Core.Accounts;

/// <summary>One local account on this machine.</summary>
/// <param name="Name">The account name as Windows knows it.</param>
/// <param name="Sid">Its SID, which is the only part that cannot be renamed.</param>
/// <param name="IsAdministrator">A member of the local Administrators group.</param>
/// <param name="IsEnabled">Windows will let somebody sign in with it.</param>
/// <param name="IsBuiltIn">Shipped with Windows rather than created here.</param>
/// <param name="PasswordNeverExpires">Its password has no expiry set.</param>
/// <param name="LastLogon">When it last signed in, or null if it never has.</param>
public sealed record LocalAccount(
    string Name,
    string Sid,
    bool IsAdministrator,
    bool IsEnabled,
    bool IsBuiltIn,
    bool PasswordNeverExpires,
    DateTime? LastLogon);

/// <summary>One signed-in session, as Windows' session manager reports it.</summary>
/// <param name="SessionId">The session number. 0 is the services session and has no desktop.</param>
/// <param name="User">Who is signed in, as DOMAIN\\user, or empty when nobody is.</param>
/// <param name="StationName">The session's window station — "console" for the physical screen.</param>
/// <param name="State">Active, disconnected, listening, and so on.</param>
/// <param name="ClientAddress">Where a remote session is coming from, if it is remote.</param>
public sealed record LogonSession(
    int SessionId,
    string User,
    string StationName,
    string State,
    string? ClientAddress);

/// <summary>
/// Who can sign in to this machine, and who is signed in now.
///
/// Every other page here watches what is running. This one watches who is allowed to run
/// anything at all, which is a different question and often an earlier one. An intruder who
/// has a foothold usually wants to keep it, and the durable way to keep it is not a file or a
/// registry value that a cleanup will find — it is an account. A new local administrator, the
/// Guest account quietly switched back on, an ordinary user added to Administrators: each of
/// these survives reinstalling the software, clearing the startup entries, and deleting the
/// malware. None of them shows up in a process list.
///
/// Sessions matter for the same reason from the other direction. A second person signed in
/// over the network, on a machine whose owner believes they are alone at it, is worth knowing
/// about before anything else on the screen means very much.
///
/// Everything here is read through Windows' own account and session APIs, needs no elevation
/// to enumerate, and leaves the machine exactly as it found it. Nothing is changed: accounts
/// are the one place where a wrong automated action locks the owner out of their own computer,
/// so this reports, and the person decides.
/// </summary>
public static class AccountScanner
{
    /// <summary>The well-known RIDs Windows gives its own accounts, whatever they are renamed to.</summary>
    private const int AdministratorRid = 500;
    private const int GuestRid = 501;

    private const uint UF_ACCOUNTDISABLE = 0x0002;
    private const uint UF_DONT_EXPIRE_PASSWD = 0x10000;

    private const int FilterNormalAccount = 0x0002;
    private const int LevelUserInfo3 = 3;
    private const int LevelLocalGroupMembers2 = 2;

    /// <summary>Every local account, with whether it can sign in and whether it is an administrator.</summary>
    public static IReadOnlyList<LocalAccount> Accounts()
    {
        var list = new List<LocalAccount>();
        var admins = AdministratorSids();

        IntPtr buffer = IntPtr.Zero;
        try
        {
            uint status = NetUserEnum(null, LevelUserInfo3, FilterNormalAccount, out buffer,
                -1, out uint read, out _, IntPtr.Zero);
            // 0 is success; 234 is ERROR_MORE_DATA, which still hands back this batch.
            if ((status != 0 && status != 234) || buffer == IntPtr.Zero) return list;

            int size = Marshal.SizeOf<USER_INFO_3>();
            for (int i = 0; i < read; i++)
            {
                var info = Marshal.PtrToStructure<USER_INFO_3>(buffer + i * size);
                string name = info.usri3_name ?? "";
                if (name.Length == 0) continue;

                string sid = SidFor(name) ?? "";
                int rid = (int)info.usri3_user_id;

                list.Add(new LocalAccount(
                    Name: name,
                    Sid: sid,
                    IsAdministrator: sid.Length > 0 && admins.Contains(sid),
                    IsEnabled: (info.usri3_flags & UF_ACCOUNTDISABLE) == 0,
                    IsBuiltIn: rid is AdministratorRid or GuestRid,
                    PasswordNeverExpires: (info.usri3_flags & UF_DONT_EXPIRE_PASSWD) != 0,
                    LastLogon: info.usri3_last_logon == 0
                        ? null
                        : DateTimeOffset.FromUnixTimeSeconds(info.usri3_last_logon).LocalDateTime));
            }
        }
        catch { /* the account database is unavailable; report nothing rather than guess */ }
        finally { if (buffer != IntPtr.Zero) NetApiBufferFree(buffer); }

        return list;
    }

    /// <summary>
    /// The SIDs in the local Administrators group.
    ///
    /// Looked up by its well-known SID and not by the name "Administrators", because the group
    /// can be renamed and is, on localised installations — this machine's own interface is
    /// Arabic. A check that only knows the English name would find no administrators at all and
    /// report every account as ordinary, which is the most reassuring possible way to be wrong.
    /// </summary>
    private static HashSet<string> AdministratorSids()
    {
        var sids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string? group = NameOfWellKnownAdminGroup();
        if (group is null) return sids;

        IntPtr buffer = IntPtr.Zero;
        try
        {
            uint status = NetLocalGroupGetMembers(null, group, LevelLocalGroupMembers2,
                out buffer, -1, out uint read, out _, IntPtr.Zero);
            if ((status != 0 && status != 234) || buffer == IntPtr.Zero) return sids;

            int size = Marshal.SizeOf<LOCALGROUP_MEMBERS_INFO_2>();
            for (int i = 0; i < read; i++)
            {
                var m = Marshal.PtrToStructure<LOCALGROUP_MEMBERS_INFO_2>(buffer + i * size);
                if (m.lgrmi2_sid != IntPtr.Zero &&
                    ConvertSidToStringSid(m.lgrmi2_sid, out IntPtr str) && str != IntPtr.Zero)
                {
                    string? s = Marshal.PtrToStringUni(str);
                    LocalFree(str);
                    if (!string.IsNullOrEmpty(s)) sids.Add(s);
                }
            }
        }
        catch { /* not readable here */ }
        finally { if (buffer != IntPtr.Zero) NetApiBufferFree(buffer); }

        return sids;
    }

    /// <summary>Resolves S-1-5-32-544 to whatever this installation calls that group.</summary>
    private static string? NameOfWellKnownAdminGroup()
    {
        try
        {
            var sid = new System.Security.Principal.SecurityIdentifier(
                System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null);
            var account = (System.Security.Principal.NTAccount)
                sid.Translate(typeof(System.Security.Principal.NTAccount));

            string name = account.Value;
            int slash = name.IndexOf('\\');
            return slash >= 0 ? name[(slash + 1)..] : name;
        }
        catch { return null; }
    }

    private static string? SidFor(string accountName)
    {
        try
        {
            var account = new System.Security.Principal.NTAccount(Environment.MachineName, accountName);
            return account.Translate(typeof(System.Security.Principal.SecurityIdentifier)).Value;
        }
        catch { return null; }
    }

    /// <summary>Every session the machine knows about, signed in or waiting.</summary>
    public static IReadOnlyList<LogonSession> Sessions()
    {
        var list = new List<LogonSession>();
        IntPtr sessions = IntPtr.Zero;

        try
        {
            if (!WTSEnumerateSessions(IntPtr.Zero, 0, 1, out sessions, out int count) || count <= 0)
                return list;

            int size = Marshal.SizeOf<WTS_SESSION_INFO>();
            for (int i = 0; i < count; i++)
            {
                var s = Marshal.PtrToStructure<WTS_SESSION_INFO>(sessions + i * size);

                string user = Query(s.SessionId, WTSUserName);
                string domain = Query(s.SessionId, WTSDomainName);
                string client = Query(s.SessionId, WTSClientAddressText);

                list.Add(new LogonSession(
                    SessionId: s.SessionId,
                    User: user.Length == 0 ? "" : (domain.Length > 0 ? $@"{domain}\{user}" : user),
                    StationName: s.WinStationName ?? "",
                    State: StateName(s.State),
                    ClientAddress: client.Length == 0 ? null : client));
            }
        }
        catch { /* the session manager is unavailable */ }
        finally { if (sessions != IntPtr.Zero) WTSFreeMemory(sessions); }

        return list;
    }

    private const int WTSUserName = 5;
    private const int WTSDomainName = 7;
    private const int WTSClientAddressText = 14;   // WTSClientName; the readable one

    private static string Query(int sessionId, int cls)
    {
        IntPtr buffer = IntPtr.Zero;
        try
        {
            if (!WTSQuerySessionInformation(IntPtr.Zero, sessionId, cls, out buffer, out _) ||
                buffer == IntPtr.Zero)
                return "";
            return Marshal.PtrToStringUni(buffer) ?? "";
        }
        catch { return ""; }
        finally { if (buffer != IntPtr.Zero) WTSFreeMemory(buffer); }
    }

    private static string StateName(int state) => state switch
    {
        0 => "active",
        1 => "connecting",
        2 => "connected",
        3 => "shadowing",
        4 => "disconnected",
        5 => "idle",
        6 => "listening",
        7 => "reset",
        8 => "down",
        9 => "initialising",
        _ => "unknown",
    };

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct USER_INFO_3
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string usri3_name;
        [MarshalAs(UnmanagedType.LPWStr)] public string usri3_password;
        public uint usri3_password_age;
        public uint usri3_priv;
        [MarshalAs(UnmanagedType.LPWStr)] public string usri3_home_dir;
        [MarshalAs(UnmanagedType.LPWStr)] public string usri3_comment;
        public uint usri3_flags;
        [MarshalAs(UnmanagedType.LPWStr)] public string usri3_script_path;
        public uint usri3_auth_flags;
        [MarshalAs(UnmanagedType.LPWStr)] public string usri3_full_name;
        [MarshalAs(UnmanagedType.LPWStr)] public string usri3_usr_comment;
        [MarshalAs(UnmanagedType.LPWStr)] public string usri3_parms;
        [MarshalAs(UnmanagedType.LPWStr)] public string usri3_workstations;
        public uint usri3_last_logon;
        public uint usri3_last_logoff;
        public uint usri3_acct_expires;
        public uint usri3_max_storage;
        public uint usri3_units_per_week;
        public IntPtr usri3_logon_hours;
        public uint usri3_bad_pw_count;
        public uint usri3_num_logons;
        [MarshalAs(UnmanagedType.LPWStr)] public string usri3_logon_server;
        public uint usri3_country_code;
        public uint usri3_code_page;
        public uint usri3_user_id;
        public uint usri3_primary_group_id;
        [MarshalAs(UnmanagedType.LPWStr)] public string usri3_profile;
        [MarshalAs(UnmanagedType.LPWStr)] public string usri3_home_dir_drive;
        public uint usri3_password_expired;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LOCALGROUP_MEMBERS_INFO_2
    {
        public IntPtr lgrmi2_sid;
        public int lgrmi2_sidusage;
        [MarshalAs(UnmanagedType.LPWStr)] public string lgrmi2_domainandname;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WTS_SESSION_INFO
    {
        public int SessionId;
        [MarshalAs(UnmanagedType.LPWStr)] public string WinStationName;
        public int State;
    }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern uint NetUserEnum(
        string? server, int level, int filter, out IntPtr buffer, int prefMaxLen,
        out uint entriesRead, out uint totalEntries, IntPtr resumeHandle);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern uint NetLocalGroupGetMembers(
        string? server, string groupName, int level, out IntPtr buffer, int prefMaxLen,
        out uint entriesRead, out uint totalEntries, IntPtr resumeHandle);

    [DllImport("netapi32.dll")]
    private static extern uint NetApiBufferFree(IntPtr buffer);

    [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool WTSEnumerateSessions(
        IntPtr server, int reserved, int version, out IntPtr sessions, out int count);

    [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool WTSQuerySessionInformation(
        IntPtr server, int sessionId, int cls, out IntPtr buffer, out int bytesReturned);

    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr memory);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "ConvertSidToStringSidW")]
    private static extern bool ConvertSidToStringSid(IntPtr sid, out IntPtr stringSid);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr mem);
}
