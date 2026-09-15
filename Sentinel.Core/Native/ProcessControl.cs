using System.Runtime.InteropServices;

namespace Sentinel.Core.Native;

/// <summary>
/// Suspend / resume a whole process — the same freeze a task monitor offers, so a suspicious
/// process can be halted for inspection without killing it (and losing the evidence). Uses the
/// ntdll process-wide suspend, which is atomic across all threads.
/// </summary>
public static class ProcessControl
{
    private const uint PROCESS_SUSPEND_RESUME = 0x0800;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("ntdll.dll")]
    private static extern uint NtSuspendProcess(IntPtr handle);

    [DllImport("ntdll.dll")]
    private static extern uint NtResumeProcess(IntPtr handle);

    public static bool Suspend(int pid) => Do(pid, NtSuspendProcess);
    public static bool Resume(int pid) => Do(pid, NtResumeProcess);

    private static bool Do(int pid, Func<IntPtr, uint> op)
    {
        IntPtr h = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid);
        if (h == IntPtr.Zero) return false;
        try { return op(h) == 0; }
        finally { CloseHandle(h); }
    }
}
