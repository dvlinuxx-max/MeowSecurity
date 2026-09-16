using System.Runtime.InteropServices;

namespace MeowSecurity.Core.Native;

/// <summary>
/// Minimal native surface we need for process discovery. We deliberately reach two
/// different sources — the Toolhelp snapshot (via the managed Process class) and the
/// native NtQuerySystemInformation list — so we can diff them and surface anything that
/// hides from one but not the other.
/// </summary>
internal static class NtApi
{
    public const int SystemProcessInformation = 5;
    public const uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;

    [DllImport("ntdll.dll")]
    public static extern uint NtQuerySystemInformation(
        int systemInformationClass,
        IntPtr systemInformation,
        int systemInformationLength,
        out int returnLength);

    // SYSTEM_PROCESS_INFORMATION is a variable-length record chain. We only read the
    // few fields we care about (offset to next, PID, image name) by hand rather than
    // marshalling the whole struct, which keeps this robust across Windows builds.
    public readonly struct ProcessRecord(int pid, int parentPid, string name)
    {
        public int Pid { get; } = pid;
        public int ParentPid { get; } = parentPid;
        public string Name { get; } = name;
    }
}
