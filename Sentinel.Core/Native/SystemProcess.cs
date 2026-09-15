using System.Runtime.InteropServices;

namespace Sentinel.Core.Native;

/// <summary>
/// One raw record from NtQuerySystemInformation(SystemProcessInformation), with the live
/// performance counters a monitor needs — CPU times, memory, I/O — read by hand at fixed
/// x64 offsets. This is the cheap once-per-tick source that lets numbers move like a real
/// task manager without opening every process handle.
/// </summary>
public readonly struct SystemProcess(
    int pid, int parentPid, int sessionId, string name,
    int threads, int handles, long kernelTime, long userTime,
    long workingSet, long privateBytes, long ioBytes)
{
    public int Pid { get; } = pid;
    public int ParentPid { get; } = parentPid;
    public int SessionId { get; } = sessionId;
    public string Name { get; } = name;
    public int Threads { get; } = threads;
    public int Handles { get; } = handles;

    /// <summary>Kernel + user CPU time in 100-ns units (cumulative since start).</summary>
    public long CpuTime100ns { get; } = kernelTime + userTime;

    public long WorkingSet { get; } = workingSet;
    public long PrivateBytes { get; } = privateBytes;

    /// <summary>Read + write + other transfer bytes (cumulative since start).</summary>
    public long IoBytes { get; } = ioBytes;
}

/// <summary>
/// Walks the SYSTEM_PROCESS_INFORMATION chain and reads the full set of live counters.
/// Kept separate from <see cref="ProcessQuery"/> (which only needs PID/name for the
/// hidden-process diff) so the security scan and the live monitor stay independent.
/// </summary>
public static class SystemProcessSnapshot
{
    // SYSTEM_PROCESS_INFORMATION (x64) field offsets we read:
    //   0x00 ULONG NextEntryOffset
    //   0x04 ULONG NumberOfThreads
    //   0x28 LARGE_INTEGER UserTime        (100-ns)
    //   0x30 LARGE_INTEGER KernelTime      (100-ns)
    //   0x38 UNICODE_STRING ImageName { USHORT Length; USHORT Max; PWSTR Buffer@0x40 }
    //   0x50 HANDLE UniqueProcessId
    //   0x58 HANDLE InheritedFromUniqueProcessId
    //   0x60 ULONG HandleCount
    //   0x64 ULONG SessionId
    //   0x90 SIZE_T WorkingSetSize          (bytes)
    //   0xB8 SIZE_T PagefileUsage           (bytes, ~ private commit)
    //   0xE8 LARGE_INTEGER ReadTransferCount
    //   0xF0 LARGE_INTEGER WriteTransferCount
    //   0xF8 LARGE_INTEGER OtherTransferCount
    public static List<SystemProcess> Enumerate()
    {
        var result = new List<SystemProcess>(256);
        int length = 1024 * 1024;
        IntPtr buffer = Marshal.AllocHGlobal(length);
        try
        {
            uint status;
            while ((status = NtApi.NtQuerySystemInformation(
                       NtApi.SystemProcessInformation, buffer, length, out int needed))
                   == NtApi.STATUS_INFO_LENGTH_MISMATCH)
            {
                Marshal.FreeHGlobal(buffer);
                length = Math.Max(needed, length) + 128 * 1024;
                buffer = Marshal.AllocHGlobal(length);
            }
            if (status != 0)
                return result;

            IntPtr entry = buffer;
            while (true)
            {
                int nextOffset = Marshal.ReadInt32(entry, 0x00);
                int threads = Marshal.ReadInt32(entry, 0x04);
                long userTime = Marshal.ReadInt64(entry, 0x28);
                long kernelTime = Marshal.ReadInt64(entry, 0x30);

                ushort nameLen = (ushort)Marshal.ReadInt16(entry, 0x38);
                IntPtr namePtr = Marshal.ReadIntPtr(entry, 0x40);
                long pid = Marshal.ReadIntPtr(entry, 0x50).ToInt64();
                long ppid = Marshal.ReadIntPtr(entry, 0x58).ToInt64();
                int handles = Marshal.ReadInt32(entry, 0x60);
                int session = Marshal.ReadInt32(entry, 0x64);
                long workingSet = Marshal.ReadIntPtr(entry, 0x90).ToInt64();
                long privateBytes = Marshal.ReadIntPtr(entry, 0xB8).ToInt64();
                long readXfer = Marshal.ReadInt64(entry, 0xE8);
                long writeXfer = Marshal.ReadInt64(entry, 0xF0);
                long otherXfer = Marshal.ReadInt64(entry, 0xF8);

                string name = nameLen > 0 && namePtr != IntPtr.Zero
                    ? Marshal.PtrToStringUni(namePtr, nameLen / 2)
                    : pid == 0 ? "System Idle Process" : string.Empty;

                result.Add(new SystemProcess(
                    (int)pid, (int)ppid, session, name, threads, handles,
                    kernelTime, userTime, workingSet, privateBytes,
                    readXfer + writeXfer + otherXfer));

                if (nextOffset == 0)
                    break;
                entry += nextOffset;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
        return result;
    }
}
