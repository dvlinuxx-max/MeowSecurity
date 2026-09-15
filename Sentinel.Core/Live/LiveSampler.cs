using System.Diagnostics;
using System.Runtime.InteropServices;
using Sentinel.Core.Native;

namespace Sentinel.Core.Live;

/// <summary>
/// Turns two raw NtQuerySystemInformation snapshots into live rates. Each tick it reads the
/// cumulative CPU/I/O counters, differences them against the previous tick over the real
/// elapsed time, and yields per-process CPU% and I/O bytes/sec plus a machine-wide pulse.
/// Cheap enough to run every second; security enrichment happens elsewhere.
/// </summary>
public sealed class LiveSampler
{
    private readonly int _cpuCount = Environment.ProcessorCount;
    private readonly Dictionary<int, (long cpu, long io)> _prev = new();
    private long _prevTimestamp;

    private long _prevIdle, _prevKernel, _prevUser;
    private ulong _prevNetIn, _prevNetOut;

    public IReadOnlyList<LiveProcess> Sample(out SystemPulse pulse)
    {
        long now = Stopwatch.GetTimestamp();
        double seconds = _prevTimestamp == 0
            ? 0
            : (now - _prevTimestamp) / (double)Stopwatch.Frequency;
        if (seconds <= 0) seconds = 1; // first tick: report cumulative-as-is, avoid div/0

        var raw = SystemProcessSnapshot.Enumerate();
        var list = new List<LiveProcess>(raw.Count);
        var seen = new Dictionary<int, (long cpu, long io)>(raw.Count);
        int threadTotal = 0;

        foreach (var p in raw)
        {
            seen[p.Pid] = (p.CpuTime100ns, p.IoBytes);
            threadTotal += p.Threads;

            double cpuPercent = 0;
            long ioRate = 0;
            if (_prevTimestamp != 0 && _prev.TryGetValue(p.Pid, out var was))
            {
                long dCpu = p.CpuTime100ns - was.cpu;          // 100-ns units
                if (dCpu > 0)
                    cpuPercent = dCpu / (seconds * 1e7) / _cpuCount * 100.0;
                long dIo = p.IoBytes - was.io;
                if (dIo > 0) ioRate = (long)(dIo / seconds);
            }

            list.Add(new LiveProcess
            {
                Pid = p.Pid,
                ParentPid = p.ParentPid,
                SessionId = p.SessionId,
                Name = string.IsNullOrEmpty(p.Name) ? "(unknown)" : p.Name,
                Threads = p.Threads,
                Handles = p.Handles,
                WorkingSet = p.WorkingSet,
                PrivateBytes = p.PrivateBytes,
                CpuPercent = Math.Clamp(cpuPercent, 0, 100),
                IoBytesPerSec = ioRate,
            });
        }

        _prev.Clear();
        foreach (var kv in seen) _prev[kv.Key] = kv.Value;

        pulse = BuildPulse(raw.Count, threadTotal, seconds);
        _prevTimestamp = now;
        return list;
    }

    private SystemPulse BuildPulse(int procCount, int threadTotal, double seconds)
    {
        // Total CPU% from GetSystemTimes: busy fraction = 1 - idle/(kernel+user).
        double cpu = 0;
        if (GetSystemTimes(out long idle, out long kernel, out long user))
        {
            if (_prevKernel != 0)
            {
                long dIdle = idle - _prevIdle;
                long dBusy = (kernel - _prevKernel) + (user - _prevUser);
                if (dBusy > 0) cpu = (dBusy - dIdle) / (double)dBusy * 100.0;
            }
            _prevIdle = idle; _prevKernel = kernel; _prevUser = user;
        }

        long memUsed = 0, memTotal = 0;
        var mem = new MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>() };
        if (GlobalMemoryStatusEx(ref mem))
        {
            memTotal = (long)mem.ullTotalPhys;
            memUsed = (long)(mem.ullTotalPhys - mem.ullAvailPhys);
        }

        long netIn = 0, netOut = 0;
        var (curIn, curOut) = IfTable.TotalOctets();
        if (_prevNetIn != 0 || _prevNetOut != 0)
        {
            if (curIn >= _prevNetIn) netIn = (long)((curIn - _prevNetIn) / seconds);
            if (curOut >= _prevNetOut) netOut = (long)((curOut - _prevNetOut) / seconds);
        }
        _prevNetIn = curIn; _prevNetOut = curOut;

        return new SystemPulse(
            Math.Clamp(cpu, 0, 100), memUsed, memTotal, netIn, netOut, procCount, threadTotal);
    }

    [DllImport("kernel32.dll")]
    private static extern bool GetSystemTimes(out long idle, out long kernel, out long user);

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORYSTATUSEX
    {
        public uint dwLength;
        public uint dwMemoryLoad;
        public ulong ullTotalPhys;
        public ulong ullAvailPhys;
        public ulong ullTotalPageFile;
        public ulong ullAvailPageFile;
        public ulong ullTotalVirtual;
        public ulong ullAvailVirtual;
        public ulong ullAvailExtendedVirtual;
    }

    [DllImport("kernel32.dll")]
    private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX buffer);
}
