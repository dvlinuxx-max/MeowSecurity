using System.Runtime.InteropServices;

namespace MeowSecurity.Core.Native;

/// <summary>What one process is holding open against another, and how much access it asked for.</summary>
/// <param name="HolderPid">The process that owns the handle.</param>
/// <param name="TargetPid">The process the handle refers to.</param>
/// <param name="GrantedAccess">The access mask the handle actually carries.</param>
public readonly record struct ProcessHandle(int HolderPid, int TargetPid, uint GrantedAccess)
{
    /// <summary>Read another process's memory — how a credential dumper reaches LSASS.</summary>
    public bool CanReadMemory => (GrantedAccess & HandleTable.PROCESS_VM_READ) != 0;

    /// <summary>Write into another process and start code there — the injection triad.</summary>
    public bool CanInject =>
        (GrantedAccess & (HandleTable.PROCESS_VM_WRITE | HandleTable.PROCESS_CREATE_THREAD)) != 0;
}

/// <summary>
/// The machine's handle table, read for one question: who is holding another process open,
/// and what were they allowed to do with it.
///
/// This is the signal no amount of file inspection can give you. Credential theft does not
/// need a new binary or a suspicious command line — it needs a handle to LSASS with read
/// access, and that is true whether the tool is Mimikatz, a signed debugger, or a hundred
/// lines someone wrote this morning. The handle is the act itself, so it is the thing worth
/// watching.
///
/// Two limits are worth stating plainly. Enumerating the table needs no privilege, but
/// resolving what a handle points at means duplicating it, which needs PROCESS_DUP_HANDLE on
/// the holder — granted for processes running as this user, refused for most system ones.
/// Unelevated, then, this sees the half of the machine an ordinary attacker actually lives
/// in; elevated it sees all of it. Rather than pretend otherwise, <see cref="Resolve"/>
/// reports how many holders it could not open, so the caller can say so.
/// </summary>
public static class HandleTable
{
    public const uint PROCESS_CREATE_THREAD = 0x0002;
    public const uint PROCESS_VM_OPERATION = 0x0008;
    public const uint PROCESS_VM_READ = 0x0010;
    public const uint PROCESS_VM_WRITE = 0x0020;

    private const uint PROCESS_DUP_HANDLE = 0x0040;
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    private const int SystemExtendedHandleInformation = 64;
    private const uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;
    private const uint DUPLICATE_SAME_ACCESS = 0x0002;

    // SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, x64: a fixed 40-byte record we read field by field
    // rather than marshalling, the same way the process list is read elsewhere here.
    private const int EntrySize = 40;
    private const int HeaderSize = 16;          // NumberOfHandles + Reserved, both pointer-sized
    private const int OffsetOwnerPid = 8;
    private const int OffsetHandleValue = 16;
    private const int OffsetGrantedAccess = 24;
    private const int OffsetTypeIndex = 30;

    /// <summary>
    /// Every cross-process handle on the machine that carries memory or thread access, resolved
    /// to the process it names. One pass answers every question worth asking of it — who can
    /// read LSASS, who can write into a neighbour — because reading the table repeatedly, once
    /// per target, would cost far more than reading it once and sorting the answers out here.
    ///
    /// A process's handles to itself are left out: every process holds those and they mean
    /// nothing.
    /// </summary>
    /// <param name="unreadableHolders">
    /// How many holders could not be opened, and whose handles therefore went unexamined. A
    /// non-zero count means the answer is a floor, not a total.
    /// </param>
    public static IReadOnlyList<ProcessHandle> ScanDangerous(out int unreadableHolders)
    {
        unreadableHolders = 0;
        var found = new List<ProcessHandle>();
        int ownPid = Environment.ProcessId;

        // This handle has to exist *before* the snapshot is taken, or it will not be in it —
        // and it is the only thing that tells us which type index means "Process" on this
        // kernel. Opening it afterwards was silently reading an empty machine.
        IntPtr known = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, ownPid);
        if (known == IntPtr.Zero) return found;

        byte[]? table;
        ushort processType;
        int count;
        try
        {
            table = ReadTable(out count);
            if (table is null) return found;
            if (!TryFindProcessTypeIndex(table, count, ownPid, known, out processType))
                return found;
        }
        finally { CloseHandle(known); }
        var refused = new HashSet<int>();
        var holders = new Dictionary<int, IntPtr>();

        try
        {
            for (int i = 0; i < count; i++)
            {
                int at = HeaderSize + i * EntrySize;
                if (BitConverter.ToUInt16(table, at + OffsetTypeIndex) != processType) continue;

                int holderPid = (int)BitConverter.ToInt64(table, at + OffsetOwnerPid);
                uint access = BitConverter.ToUInt32(table, at + OffsetGrantedAccess);

                // Our own handles are the ones this scan just opened, so counting them would be
                // self-indictment; the idle and system PIDs are noise.
                if (holderPid == ownPid || holderPid <= 4) continue;

                // Only masks that let the holder do something to the target are worth the cost
                // of a duplicate — which is what turns a 100,000-entry table into a few dozen.
                if ((access & (PROCESS_VM_READ | PROCESS_VM_WRITE |
                               PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD)) == 0) continue;

                if (refused.Contains(holderPid)) continue;
                if (!holders.TryGetValue(holderPid, out IntPtr holder))
                {
                    holder = OpenProcess(PROCESS_DUP_HANDLE, false, holderPid);
                    if (holder == IntPtr.Zero)
                    {
                        refused.Add(holderPid);
                        unreadableHolders++;
                        continue;
                    }
                    holders[holderPid] = holder;
                }

                IntPtr value = new(BitConverter.ToInt64(table, at + OffsetHandleValue));
                int targetPid = ResolveTarget(holder, value);

                // A process holding itself open is universal and says nothing.
                if (targetPid > 0 && targetPid != holderPid)
                    found.Add(new ProcessHandle(holderPid, targetPid, access));
            }
        }
        finally
        {
            foreach (IntPtr h in holders.Values) CloseHandle(h);
        }

        return found;
    }

    /// <summary>Duplicates one handle just far enough to ask which process it names.</summary>
    private static int ResolveTarget(IntPtr holder, IntPtr handleValue)
    {
        IntPtr copy = IntPtr.Zero;
        try
        {
            if (!DuplicateHandle(holder, handleValue, CurrentProcess, out copy,
                    PROCESS_QUERY_LIMITED_INFORMATION, false, 0) || copy == IntPtr.Zero)
            {
                // Some handles cannot be duplicated with reduced access; ask for the original.
                if (!DuplicateHandle(holder, handleValue, CurrentProcess, out copy,
                        0, false, DUPLICATE_SAME_ACCESS) || copy == IntPtr.Zero)
                    return 0;
            }
            return GetProcessId(copy);
        }
        catch { return 0; }
        finally { if (copy != IntPtr.Zero) CloseHandle(copy); }
    }

    /// <summary>
    /// Learns which type index means "Process" on this machine rather than hard-coding one.
    ///
    /// The indexes are assigned in the order the kernel creates object types and have moved
    /// between Windows builds. We already hold a handle we know to be a process — our own —
    /// so we look that one up in the table and read the index off it. A number derived from
    /// the running kernel cannot be wrong about the running kernel.
    /// </summary>
    private static bool TryFindProcessTypeIndex(
        byte[] table, int count, int ownPid, IntPtr known, out ushort typeIndex)
    {
        typeIndex = 0;
        long needle = known.ToInt64();

        for (int i = 0; i < count; i++)
        {
            int at = HeaderSize + i * EntrySize;
            if ((int)BitConverter.ToInt64(table, at + OffsetOwnerPid) != ownPid) continue;
            if (BitConverter.ToInt64(table, at + OffsetHandleValue) != needle) continue;

            typeIndex = BitConverter.ToUInt16(table, at + OffsetTypeIndex);
            return true;
        }
        return false;
    }

    /// <summary>
    /// Snapshots the handle table. It grows between the sizing call and the read — every new
    /// handle on the machine changes it — so the buffer is asked for with headroom and the
    /// call is retried rather than trusted once.
    /// </summary>
    private static byte[]? ReadTable(out int count)
    {
        count = 0;
        int size = 1 << 20;

        for (int attempt = 0; attempt < 6; attempt++)
        {
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                uint status = NtApi.NtQuerySystemInformation(
                    SystemExtendedHandleInformation, buffer, size, out int needed);

                if (status == STATUS_INFO_LENGTH_MISMATCH)
                {
                    size = Math.Max(needed, size * 2) + (64 * 1024);
                    continue;
                }
                if (status != 0) return null;

                long handles = Marshal.ReadInt64(buffer);
                if (handles <= 0) return null;

                // Trust the buffer we were given, not the count in it, if the two disagree.
                long capacity = (size - HeaderSize) / EntrySize;
                count = (int)Math.Min(handles, capacity);

                var managed = new byte[HeaderSize + (long)count * EntrySize];
                Marshal.Copy(buffer, managed, 0, managed.Length);
                return managed;
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        return null;
    }

    private static readonly IntPtr CurrentProcess = GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int GetProcessId(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DuplicateHandle(
        IntPtr sourceProcess, IntPtr sourceHandle, IntPtr targetProcess,
        out IntPtr targetHandle, uint desiredAccess, bool inherit, uint options);
}
