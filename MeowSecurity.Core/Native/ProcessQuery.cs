using System.Runtime.InteropServices;

namespace MeowSecurity.Core.Native;

/// <summary>
/// Reads the raw process list straight from ntdll's NtQuerySystemInformation. This is a
/// lower-level view than the managed Process class (which uses the Toolhelp snapshot),
/// and the two disagreeing is itself a signal.
/// </summary>
internal static class ProcessQuery
{
    public static List<NtApi.ProcessRecord> FromNtQuery()
    {
        var result = new List<NtApi.ProcessRecord>();
        int length = 512 * 1024;
        IntPtr buffer = Marshal.AllocHGlobal(length);
        try
        {
            uint status;
            // The list grows between calls; loop until the buffer is big enough.
            while ((status = NtApi.NtQuerySystemInformation(
                       NtApi.SystemProcessInformation, buffer, length, out int needed))
                   == NtApi.STATUS_INFO_LENGTH_MISMATCH)
            {
                Marshal.FreeHGlobal(buffer);
                length = Math.Max(needed, length) + 64 * 1024;
                buffer = Marshal.AllocHGlobal(length);
            }
            if (status != 0)
                return result;

            IntPtr entry = buffer;
            while (true)
            {
                // Layout of SYSTEM_PROCESS_INFORMATION (x64), fields we use:
                //   0x00 ULONG NextEntryOffset
                //   0x38 UNICODE_STRING ImageName { USHORT Length; USHORT Max; PWSTR Buffer }
                //   0x50 HANDLE UniqueProcessId
                //   0x58 HANDLE InheritedFromUniqueProcessId
                int nextOffset = Marshal.ReadInt32(entry, 0x00);
                long pid = Marshal.ReadIntPtr(entry, 0x50).ToInt64();
                long ppid = Marshal.ReadIntPtr(entry, 0x58).ToInt64();

                ushort nameLen = (ushort)Marshal.ReadInt16(entry, 0x38);
                IntPtr namePtr = Marshal.ReadIntPtr(entry, 0x40);
                string name = nameLen > 0 && namePtr != IntPtr.Zero
                    ? Marshal.PtrToStringUni(namePtr, nameLen / 2)
                    : pid == 0 ? "System Idle Process" : string.Empty;

                result.Add(new NtApi.ProcessRecord((int)pid, (int)ppid, name));

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
