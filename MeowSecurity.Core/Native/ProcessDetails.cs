using System.Runtime.InteropServices;

namespace MeowSecurity.Core.Native;

/// <summary>
/// Reads a process's full command line. The image name alone rarely tells you what a
/// process is doing — a malicious payload usually lives in the arguments to a trusted host
/// like powershell.exe, rundll32.exe or mshta.exe. Uses the documented (Win8.1+)
/// ProcessCommandLineInformation class, so no PEB spelunking.
/// </summary>
public static class ProcessDetails
{
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const int ProcessCommandLineInformation = 60;
    private const uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("ntdll.dll")]
    private static extern uint NtQueryInformationProcess(
        IntPtr handle, int cls, IntPtr buffer, int length, out int returnLength);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(
        IntPtr handle, uint flags, System.Text.StringBuilder buffer, ref int size);

    /// <summary>
    /// The path of the running image.
    ///
    /// The managed <c>Process.MainModule</c> needs PROCESS_VM_READ — it walks the module list
    /// inside the target — so without administrator rights it fails for almost every process
    /// on the machine, and with it go the signature and publisher that are derived from the
    /// path. QueryFullProcessImageName only needs PROCESS_QUERY_LIMITED_INFORMATION, which an
    /// ordinary user is granted for ordinary processes, so the columns fill in either way.
    /// </summary>
    public static string? GetImagePath(int pid)
    {
        if (pid <= 4) return null;   // Idle and System have no image on disk
        IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            int size = 1024;
            var sb = new System.Text.StringBuilder(size);
            return QueryFullProcessImageName(h, 0, sb, ref size) && sb.Length > 0
                ? sb.ToString()
                : null;
        }
        catch { return null; }
        finally { CloseHandle(h); }
    }

    public static string? GetCommandLine(int pid)
    {
        IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return null;
        IntPtr buffer = IntPtr.Zero;
        try
        {
            uint status = NtQueryInformationProcess(h, ProcessCommandLineInformation, IntPtr.Zero, 0, out int need);
            if (status != STATUS_INFO_LENGTH_MISMATCH || need <= 0) return null;

            buffer = Marshal.AllocHGlobal(need);
            if (NtQueryInformationProcess(h, ProcessCommandLineInformation, buffer, need, out _) != 0)
                return null;

            // Buffer holds a UNICODE_STRING (x64): USHORT Length @0, PWSTR Buffer @8.
            ushort len = (ushort)Marshal.ReadInt16(buffer, 0);
            IntPtr strPtr = Marshal.ReadIntPtr(buffer, 8);
            if (len == 0 || strPtr == IntPtr.Zero) return null;
            return Marshal.PtrToStringUni(strPtr, len / 2);
        }
        catch { return null; }
        finally
        {
            if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
            CloseHandle(h);
        }
    }
}
