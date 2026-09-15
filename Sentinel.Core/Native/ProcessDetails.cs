using System.Runtime.InteropServices;

namespace Sentinel.Core.Native;

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
