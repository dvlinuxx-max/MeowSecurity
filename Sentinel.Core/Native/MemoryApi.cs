using System.Runtime.InteropServices;

namespace Sentinel.Core.Native;

/// <summary>Process memory + module enumeration used by the injection detector.</summary>
internal static class MemoryApi
{
    [Flags]
    public enum ProcessAccess : uint
    {
        QueryInformation = 0x0400,
        VmRead = 0x0010,
    }

    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_PRIVATE = 0x20000;
    public const uint MEM_IMAGE = 0x1000000;
    public const uint MEM_MAPPED = 0x40000;

    public const uint PAGE_EXECUTE = 0x10;
    public const uint PAGE_EXECUTE_READ = 0x20;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;
    public const uint PAGE_EXECUTE_WRITECOPY = 0x80;

    public static bool IsExecutable(uint protect) =>
        (protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                    PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;

    public static bool IsWritableAndExecutable(uint protect) =>
        (protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public ushort PartitionId;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(ProcessAccess access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr h);

    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualQueryEx(
        IntPtr hProcess, IntPtr address, out MEMORY_BASIC_INFORMATION mbi, IntPtr length);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(
        IntPtr hProcess, IntPtr baseAddress, byte[] buffer, IntPtr size, out IntPtr read);

    [DllImport("psapi.dll", SetLastError = true)]
    public static extern bool EnumProcessModulesEx(
        IntPtr hProcess, [Out] IntPtr[]? modules, uint cb, out uint needed, uint filter);

    public const uint LIST_MODULES_ALL = 0x03;
}
