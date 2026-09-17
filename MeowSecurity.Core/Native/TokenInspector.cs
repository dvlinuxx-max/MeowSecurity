using System.Runtime.InteropServices;

namespace MeowSecurity.Core.Native;

/// <summary>How much authority a process is actually running with.</summary>
/// <param name="Integrity">Windows' integrity level: Low, Medium, High or System.</param>
/// <param name="IsSystem">Running as the machine itself — the highest authority there is.</param>
/// <param name="DebugPrivilege">Holds SeDebugPrivilege *enabled*, the key to every other process.</param>
/// <param name="Impersonating">Acting under a token borrowed from somebody else.</param>
public readonly record struct TokenFacts(
    IntegrityLevel Integrity, bool IsSystem, bool DebugPrivilege, bool Impersonating)
{
    public static readonly TokenFacts Unknown = new(IntegrityLevel.Unknown, false, false, false);
}

public enum IntegrityLevel { Unknown, Low, Medium, High, System }

/// <summary>
/// Reads the token a process is running under.
///
/// Privilege escalation leaves no trace in a file, a path or a command line — the binary that
/// ends up running as SYSTEM is often the same binary that started as the user. What changes
/// is the token, so the token is where to look.
///
/// Two things here are worth more than the rest. SeDebugPrivilege, when it is *enabled* and
/// not merely present, is the master key: it lets a process open any other process on the
/// machine regardless of who owns it, and almost nothing outside a debugger or a backup agent
/// needs it. And impersonation is how a stolen token gets used — a process acting under
/// somebody else's identity is doing the one thing that identity was meant to prevent.
///
/// Needs only PROCESS_QUERY_LIMITED_INFORMATION, so it reads the user's own processes without
/// elevation and returns <see cref="TokenFacts.Unknown"/> for the rest rather than guessing.
/// </summary>
public static class TokenInspector
{
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const uint TOKEN_QUERY = 0x0008;

    private const int TokenUser = 1;
    private const int TokenPrivileges = 3;
    private const int TokenIntegrityLevel = 25;

    private const uint SE_PRIVILEGE_ENABLED = 0x00000002;
    private const uint SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001;

    // The RIDs Windows assigns to each mandatory integrity level.
    private const uint SECURITY_MANDATORY_LOW_RID = 0x1000;
    private const uint SECURITY_MANDATORY_MEDIUM_RID = 0x2000;
    private const uint SECURITY_MANDATORY_HIGH_RID = 0x3000;
    private const uint SECURITY_MANDATORY_SYSTEM_RID = 0x4000;

    private static readonly string LocalSystemSid = "S-1-5-18";

    public static TokenFacts Read(int pid)
    {
        if (pid <= 4) return TokenFacts.Unknown;

        IntPtr process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (process == IntPtr.Zero) return TokenFacts.Unknown;

        IntPtr token = IntPtr.Zero;
        try
        {
            if (!OpenProcessToken(process, TOKEN_QUERY, out token) || token == IntPtr.Zero)
                return TokenFacts.Unknown;

            var integrity = ReadIntegrity(token);
            bool system = ReadUserSid(token) == LocalSystemSid;
            bool debug = HasEnabledDebugPrivilege(token);

            // A thread running under a borrowed token is impersonation. Asking the process for
            // its *thread* token is what distinguishes "has the right to impersonate" from
            // "is impersonating right now", and only the second is worth saying.
            bool impersonating = integrity != IntegrityLevel.Unknown && IsImpersonating(pid);

            return new TokenFacts(integrity, system, debug, impersonating);
        }
        catch { return TokenFacts.Unknown; }
        finally
        {
            if (token != IntPtr.Zero) CloseHandle(token);
            CloseHandle(process);
        }
    }

    private static IntegrityLevel ReadIntegrity(IntPtr token)
    {
        IntPtr buffer = IntPtr.Zero;
        try
        {
            GetTokenInformation(token, TokenIntegrityLevel, IntPtr.Zero, 0, out int need);
            if (need <= 0) return IntegrityLevel.Unknown;

            buffer = Marshal.AllocHGlobal(need);
            if (!GetTokenInformation(token, TokenIntegrityLevel, buffer, need, out _))
                return IntegrityLevel.Unknown;

            // TOKEN_MANDATORY_LABEL is a SID_AND_ATTRIBUTES: the SID pointer comes first, and
            // the level is the SID's last sub-authority.
            IntPtr sid = Marshal.ReadIntPtr(buffer);
            if (sid == IntPtr.Zero) return IntegrityLevel.Unknown;

            IntPtr countPtr = GetSidSubAuthorityCount(sid);
            if (countPtr == IntPtr.Zero) return IntegrityLevel.Unknown;
            int count = Marshal.ReadByte(countPtr);
            if (count == 0) return IntegrityLevel.Unknown;

            uint rid = (uint)Marshal.ReadInt32(GetSidSubAuthority(sid, count - 1));

            return rid switch
            {
                >= SECURITY_MANDATORY_SYSTEM_RID => IntegrityLevel.System,
                >= SECURITY_MANDATORY_HIGH_RID => IntegrityLevel.High,
                >= SECURITY_MANDATORY_MEDIUM_RID => IntegrityLevel.Medium,
                >= SECURITY_MANDATORY_LOW_RID => IntegrityLevel.Low,
                _ => IntegrityLevel.Low,
            };
        }
        catch { return IntegrityLevel.Unknown; }
        finally { if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer); }
    }

    private static string? ReadUserSid(IntPtr token)
    {
        IntPtr buffer = IntPtr.Zero;
        try
        {
            GetTokenInformation(token, TokenUser, IntPtr.Zero, 0, out int need);
            if (need <= 0) return null;

            buffer = Marshal.AllocHGlobal(need);
            if (!GetTokenInformation(token, TokenUser, buffer, need, out _)) return null;

            IntPtr sid = Marshal.ReadIntPtr(buffer);   // TOKEN_USER.User.Sid
            if (sid == IntPtr.Zero) return null;

            return ConvertSidToStringSid(sid, out IntPtr str) && str != IntPtr.Zero
                ? MarshalAndFree(str)
                : null;
        }
        catch { return null; }
        finally { if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer); }
    }

    private static string MarshalAndFree(IntPtr str)
    {
        try { return Marshal.PtrToStringUni(str) ?? ""; }
        finally { LocalFree(str); }
    }

    /// <summary>
    /// True only when SeDebugPrivilege is present *and* switched on. Plenty of processes carry
    /// it disabled and never use it, and reporting those would be reporting nothing.
    /// </summary>
    private static bool HasEnabledDebugPrivilege(IntPtr token)
    {
        IntPtr buffer = IntPtr.Zero;
        try
        {
            GetTokenInformation(token, TokenPrivileges, IntPtr.Zero, 0, out int need);
            if (need <= 0) return false;

            buffer = Marshal.AllocHGlobal(need);
            if (!GetTokenInformation(token, TokenPrivileges, buffer, need, out _)) return false;

            if (!LookupPrivilegeValue(null, "SeDebugPrivilege", out long debugLuid)) return false;

            // TOKEN_PRIVILEGES: ULONG count, then LUID_AND_ATTRIBUTES[] of 12 bytes each.
            int count = Marshal.ReadInt32(buffer);
            for (int i = 0; i < count; i++)
            {
                int at = 4 + i * 12;
                long luid = Marshal.ReadInt64(buffer, at);
                uint attributes = (uint)Marshal.ReadInt32(buffer, at + 8);

                if (luid != debugLuid) continue;
                return (attributes & (SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT)) != 0;
            }
            return false;
        }
        catch { return false; }
        finally { if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer); }
    }

    /// <summary>
    /// Whether any thread in the process is currently running under a borrowed token.
    /// A thread has no token of its own unless it is impersonating, so the presence of one
    /// is the answer.
    /// </summary>
    private static bool IsImpersonating(int pid)
    {
        try
        {
            using var p = System.Diagnostics.Process.GetProcessById(pid);
            foreach (System.Diagnostics.ProcessThread t in p.Threads)
            {
                IntPtr thread = OpenThread(THREAD_QUERY_INFORMATION, false, t.Id);
                if (thread == IntPtr.Zero) continue;
                try
                {
                    if (OpenThreadToken(thread, TOKEN_QUERY, true, out IntPtr tok) && tok != IntPtr.Zero)
                    {
                        CloseHandle(tok);
                        return true;
                    }
                }
                finally { CloseHandle(thread); }
            }
        }
        catch { /* exited, or threads we may not ask about */ }
        return false;
    }

    private const uint THREAD_QUERY_INFORMATION = 0x0040;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenThread(uint access, bool inherit, int threadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr mem);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenThreadToken(IntPtr thread, uint access, bool openAsSelf, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(
        IntPtr token, int cls, IntPtr buffer, int length, out int returnLength);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeValue(string? system, string name, out long luid);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "ConvertSidToStringSidW")]
    private static extern bool ConvertSidToStringSid(IntPtr sid, out IntPtr stringSid);

    [DllImport("advapi32.dll")]
    private static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);

    [DllImport("advapi32.dll")]
    private static extern IntPtr GetSidSubAuthority(IntPtr sid, int index);
}
