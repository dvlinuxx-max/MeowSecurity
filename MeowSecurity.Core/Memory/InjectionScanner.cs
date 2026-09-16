using System.Runtime.InteropServices;
using MeowSecurity.Core.Native;

namespace MeowSecurity.Core.Memory;

public sealed class MemoryFinding
{
    public required IntPtr Address { get; init; }
    public required long Size { get; init; }
    public required string Kind { get; init; }   // e.g. "private executable (RWX)"
    public required string Detail { get; init; }
    public bool Rwx { get; init; }
    /// <summary>The region starts with a PE header — an implanted module, not JIT.</summary>
    public bool HasPeHeader { get; init; }
}

/// <summary>
/// Walks a process's committed memory looking for executable regions that are NOT backed
/// by an image on disk — the classic footprint of injected shellcode, reflective DLLs and
/// hollowing. This is the signal a normal task manager can't give you.
///
/// Legitimate code lives in MEM_IMAGE regions (mapped from a signed .exe/.dll on disk).
/// Executable memory that is MEM_PRIVATE (or MEM_MAPPED without an image) is either a JIT
/// (which we note but don't alarm) or an implant. We report every unbacked executable
/// region and let the scorer weigh it, giving extra weight to RWX and to regions in a
/// process that has no business JIT-compiling.
/// </summary>
public sealed class InjectionScanner
{
    public IReadOnlyList<MemoryFinding> Scan(int pid)
    {
        var findings = new List<MemoryFinding>();
        IntPtr h = MemoryApi.OpenProcess(
            MemoryApi.ProcessAccess.QueryInformation | MemoryApi.ProcessAccess.VmRead, false, pid);
        if (h == IntPtr.Zero)
            return findings; // protected process; expected for some system PIDs

        try
        {
            IntPtr address = IntPtr.Zero;
            IntPtr mbiSize = new(Marshal.SizeOf<MemoryApi.MEMORY_BASIC_INFORMATION>());
            long max = 0x00007FFFFFFFFFFF; // user-mode address ceiling on x64

            while (address.ToInt64() < max)
            {
                if (MemoryApi.VirtualQueryEx(h, address, out var mbi, mbiSize) == IntPtr.Zero)
                    break;

                long regionSize = mbi.RegionSize.ToInt64();
                if (regionSize <= 0)
                    break;

                bool committed = mbi.State == MemoryApi.MEM_COMMIT;
                bool executable = MemoryApi.IsExecutable(mbi.Protect);
                bool backedByImage = mbi.Type == MemoryApi.MEM_IMAGE;

                if (committed && executable && !backedByImage)
                {
                    bool rwx = MemoryApi.IsWritableAndExecutable(mbi.Protect);
                    bool pe = LooksLikePe(h, mbi.BaseAddress);
                    string kind = pe
                        ? "implanted PE in unbacked memory"
                        : mbi.Type == MemoryApi.MEM_PRIVATE
                            ? (rwx ? "private RWX region (unbacked)" : "private executable region (unbacked)")
                            : "mapped executable region (no image on disk)";
                    findings.Add(new MemoryFinding
                    {
                        Address = mbi.BaseAddress,
                        Size = regionSize,
                        Kind = kind,
                        Detail = $"protect=0x{mbi.Protect:X} type=0x{mbi.Type:X}",
                        Rwx = rwx,
                        HasPeHeader = pe,
                    });
                }

                long next = mbi.BaseAddress.ToInt64() + regionSize;
                if (next <= address.ToInt64())
                    break;
                address = new IntPtr(next);
            }
        }
        finally
        {
            MemoryApi.CloseHandle(h);
        }
        return findings;
    }

    // A JIT region is raw machine code; an injected DLL, a hollowed image or a reflectively
    // loaded module carries a PE header. Reading for "MZ...PE" separates real implants from
    // ordinary just-in-time compilation, which is what kills the false positives.
    private static bool LooksLikePe(IntPtr hProcess, IntPtr baseAddress)
    {
        var head = new byte[0x400];
        if (!MemoryApi.ReadProcessMemory(hProcess, baseAddress, head, new IntPtr(head.Length), out var read)
            || read.ToInt64() < 0x40)
            return false;

        if (head[0] != (byte)'M' || head[1] != (byte)'Z')
            return false;

        int peOffset = BitConverter.ToInt32(head, 0x3C);
        if (peOffset <= 0 || peOffset > head.Length - 4)
            return false;

        return head[peOffset] == (byte)'P' && head[peOffset + 1] == (byte)'E'
            && head[peOffset + 2] == 0 && head[peOffset + 3] == 0;
    }
}
