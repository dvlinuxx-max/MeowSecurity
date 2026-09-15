using System.Runtime.InteropServices;

namespace Sentinel.Core.Native;

/// <summary>
/// Machine-wide network byte counters via GetIfTable2. Summed across the live, non-loopback
/// interfaces, sampled each tick and differenced, this drives the throughput graph — the
/// same in/out octet counters a task manager's network graph is built on.
/// </summary>
public static class IfTable
{
    [DllImport("iphlpapi.dll")]
    private static extern uint GetIfTable2(out IntPtr table);

    [DllImport("iphlpapi.dll")]
    private static extern void FreeMibTable(IntPtr table);

    // MIB_IF_ROW2 is 1352 bytes on x64. We only need three fields, read at fixed offsets.
    [StructLayout(LayoutKind.Explicit, Size = 1352)]
    private struct MibIfRow2
    {
        [FieldOffset(0x468)] public uint Type;       // IF_TYPE_SOFTWARE_LOOPBACK = 24
        [FieldOffset(0x484)] public uint OperStatus;  // IfOperStatusUp = 1
        [FieldOffset(0x4B8)] public ulong InOctets;
        [FieldOffset(0x500)] public ulong OutOctets;
    }

    private const uint IfTypeSoftwareLoopback = 24;
    private const uint IfOperStatusUp = 1;

    /// <summary>Cumulative received/sent bytes across all up, non-loopback interfaces.</summary>
    public static (ulong In, ulong Out) TotalOctets()
    {
        if (GetIfTable2(out IntPtr table) != 0 || table == IntPtr.Zero)
            return (0, 0);
        try
        {
            int count = Marshal.ReadInt32(table, 0);
            int stride = Marshal.SizeOf<MibIfRow2>();
            IntPtr rows = table + 8; // ULONG NumEntries, padded to 8 for row alignment
            ulong inSum = 0, outSum = 0;
            for (int i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MibIfRow2>(rows + i * stride);
                if (row.OperStatus != IfOperStatusUp || row.Type == IfTypeSoftwareLoopback)
                    continue;
                inSum += row.InOctets;
                outSum += row.OutOctets;
            }
            return (inSum, outSum);
        }
        finally
        {
            FreeMibTable(table);
        }
    }
}
