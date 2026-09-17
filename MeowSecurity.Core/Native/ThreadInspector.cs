using System.Diagnostics;
using System.Runtime.InteropServices;

namespace MeowSecurity.Core.Native;

/// <summary>A thread whose entry point is not inside any file-backed image.</summary>
/// <param name="ThreadId">The offending thread.</param>
/// <param name="StartAddress">Where it began executing.</param>
/// <param name="Writable">The memory it started in can also be written to — RWX.</param>
public readonly record struct ForeignThread(int ThreadId, ulong StartAddress, bool Writable);

/// <summary>
/// Asks of every thread the one question a module list cannot answer: where did you start?
///
/// The memory scanner finds executable pages with no file behind them. That is half an
/// answer — unbacked memory is common enough in a JIT to be weak evidence on its own. The
/// other half is whether anything is actually *running* there, and a thread whose Win32 start
/// address lies outside every mapped image is exactly that: code executing from memory that
/// came from nowhere on disk. Together the two are a much stronger statement than either
/// alone, which is why this exists beside the memory scan rather than inside it.
///
/// Needs only PROCESS_QUERY_INFORMATION and THREAD_QUERY_INFORMATION, so it works without
/// elevation for the user's own processes and quietly returns nothing for the rest.
/// </summary>
public static class ThreadInspector
{
    private const int ThreadQuerySetWin32StartAddress = 9;
    private const uint THREAD_QUERY_INFORMATION = 0x0040;

    /// <summary>
    /// Threads in <paramref name="pid"/> that began outside any image. Empty is the normal
    /// and overwhelmingly common answer, including when the process cannot be opened.
    /// </summary>
    public static IReadOnlyList<ForeignThread> FindForeignThreads(int pid)
    {
        var found = new List<ForeignThread>();
        if (pid <= 4 || pid == Environment.ProcessId) return found;

        IntPtr process = MemoryApi.OpenProcess(MemoryApi.ProcessAccess.QueryInformation, false, pid);
        if (process == IntPtr.Zero) return found;

        try
        {
            int[] threadIds;
            try
            {
                using var p = Process.GetProcessById(pid);
                threadIds = p.Threads.Cast<ProcessThread>().Select(t => t.Id).ToArray();
            }
            catch { return found; }   // exited between the list and here

            IntPtr mbiSize = new(Marshal.SizeOf<MemoryApi.MEMORY_BASIC_INFORMATION>());

            foreach (int tid in threadIds)
            {
                ulong start = StartAddressOf(tid);
                if (start == 0) continue;

                if (MemoryApi.VirtualQueryEx(process, new IntPtr((long)start),
                        out var mbi, mbiSize) == IntPtr.Zero) continue;

                if (mbi.State != MemoryApi.MEM_COMMIT) continue;
                if (mbi.Type == MemoryApi.MEM_IMAGE) continue;      // ordinary: started in a DLL
                if (!MemoryApi.IsExecutable(mbi.Protect)) continue; // not code at all any more

                found.Add(new ForeignThread(
                    tid, start, MemoryApi.IsWritableAndExecutable(mbi.Protect)));
            }
        }
        catch { /* the process died mid-walk; report what we have */ }
        finally { MemoryApi.CloseHandle(process); }

        return found;
    }

    private static ulong StartAddressOf(int threadId)
    {
        IntPtr thread = OpenThread(THREAD_QUERY_INFORMATION, false, threadId);
        if (thread == IntPtr.Zero) return 0;

        IntPtr buffer = Marshal.AllocHGlobal(IntPtr.Size);
        try
        {
            if (NtQueryInformationThread(thread, ThreadQuerySetWin32StartAddress,
                    buffer, IntPtr.Size, out _) != 0) return 0;
            return (ulong)Marshal.ReadIntPtr(buffer).ToInt64();
        }
        catch { return 0; }
        finally
        {
            Marshal.FreeHGlobal(buffer);
            CloseHandle(thread);
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenThread(uint access, bool inherit, int threadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("ntdll.dll")]
    private static extern uint NtQueryInformationThread(
        IntPtr thread, int cls, IntPtr buffer, int length, out int returnLength);
}
