using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;

namespace MeowSecurity.Core.Etw;

/// <summary>A process the kernel told us about the moment it started.</summary>
public sealed record ProcessStart(
    DateTime TimeUtc,
    int Pid,
    int ParentPid,
    string Name,
    string? ImagePath,
    string? CommandLine,
    string? ParentName);

/// <summary>Why the watcher is not running, when it is not.</summary>
public enum EtwState
{
    Stopped,
    Running,
    NeedsElevation,
    Unavailable,
}

/// <summary>
/// Real-time process-start events, straight from the kernel.
///
/// The one-second sampler can only report what is alive when it looks, and an attack does not
/// wait to be looked at: an encoded PowerShell one-liner runs and exits inside a few hundred
/// milliseconds, leaving no trace in any poll. ETW is pushed rather than polled, so the birth
/// of every process is delivered — including the ones that are already dead by the time the
/// next tick comes round.
///
/// Uses the kernel's own process events, which carry the image name and the command line as
/// the kernel recorded them at creation — the manifest provider's ProcessStart carries neither
/// on this build, and the command line is where the payload usually hides.
///
/// Needs administrator rights: creating a trace session is a privileged operation. Without
/// them the monitor still works, it just falls back to noticing processes a tick later.
/// </summary>
public sealed class ProcessStartWatcher : IDisposable
{
    /// <summary>A named session outlives its process, so the name must be stable to reclaim it.</summary>
    private const string SessionName = "MeowSecurity-ProcessWatch";

    private TraceEventSession? _session;
    private Thread? _pump;
    private volatile bool _stopping;

    /// <summary>Raised on an ETW thread — the consumer must marshal to its own.</summary>
    public event Action<ProcessStart>? Started;

    public EtwState State { get; private set; } = EtwState.Stopped;
    public string? Error { get; private set; }

    /// <summary>Field names carried by the first start event — the provider's own manifest,
    /// which is the only reliable way to know what it actually gives us.</summary>
    public string? PayloadFields { get; private set; }

    /// <summary>Live map of pid → image name, so a child can name its parent.</summary>
    private readonly Dictionary<int, string> _names = [];
    private readonly object _namesLock = new();

    /// <summary>
    /// Bytes counted per process since the last read: [0] received, [1] sent.
    ///
    /// Windows offers no per-process byte counter — Task Manager's own network column is
    /// machine-wide — so the only way to answer "which program is uploading my files" is to
    /// add up the kernel's individual send and receive events. They arrive on the ETW thread
    /// in large numbers, hence plain interlocked adds into a fixed pair rather than anything
    /// that allocates.
    /// </summary>
    private readonly System.Collections.Concurrent.ConcurrentDictionary<int, long[]> _bytes = new();

    private void CountBytes(int pid, int size, bool incoming)
    {
        if (pid <= 0 || size <= 0) return;
        var pair = _bytes.GetOrAdd(pid, static _ => new long[2]);
        Interlocked.Add(ref pair[incoming ? 0 : 1], size);
    }

    /// <summary>
    /// Takes everything counted since the previous call and resets, so the caller divides by
    /// its own tick length to get a rate. Reading and clearing in one step is what keeps the
    /// arithmetic honest when a tick runs late.
    /// </summary>
    public Dictionary<int, (long In, long Out)> TakeNetworkTotals()
    {
        var totals = new Dictionary<int, (long, long)>(_bytes.Count);
        foreach (var (pid, pair) in _bytes)
        {
            long inBytes = Interlocked.Exchange(ref pair[0], 0);
            long outBytes = Interlocked.Exchange(ref pair[1], 0);
            if (inBytes != 0 || outBytes != 0) totals[pid] = (inBytes, outBytes);
        }
        return totals;
    }

    public bool Start()
    {
        if (State == EtwState.Running) return true;

        if (!IsElevated())
        {
            State = EtwState.NeedsElevation;
            Error = "التقاط الأحداث اللحظية يحتاج صلاحية المدير";
            return false;
        }

        try
        {
            // A session with this name may have survived a crash or a kill; taking it over is
            // the documented way to avoid leaking kernel sessions across runs.
            TraceEventSession.GetActiveSession(SessionName)?.Stop();

            _session = new TraceEventSession(SessionName) { StopOnDispose = true };

            // The kernel's own process events, not the Kernel-Process manifest provider: on
            // this build the manifest's ProcessStart carries no image name and no command
            // line, while the kernel's does — captured at creation, so it survives a process
            // that exits before anyone can ask it anything.
            _session.EnableKernelProvider(
                KernelTraceEventParser.Keywords.Process |
                KernelTraceEventParser.Keywords.NetworkTCPIP);

            _session.Source.Kernel.ProcessStart += OnProcessStart;
            _session.Source.Kernel.ProcessStop += d =>
            {
                lock (_namesLock) _names.Remove(d.ProcessID);
                _bytes.TryRemove(d.ProcessID, out _);
            };

            // Per-process throughput, counted from the individual packets the kernel reports.
            _session.Source.Kernel.TcpIpRecv += d => CountBytes(d.ProcessID, d.size, incoming: true);
            _session.Source.Kernel.TcpIpSend += d => CountBytes(d.ProcessID, d.size, incoming: false);
            _session.Source.Kernel.UdpIpRecv += d => CountBytes(d.ProcessID, d.size, incoming: true);
            _session.Source.Kernel.UdpIpSend += d => CountBytes(d.ProcessID, d.size, incoming: false);
            _session.Source.Kernel.TcpIpRecvIPV6 += d => CountBytes(d.ProcessID, d.size, incoming: true);
            _session.Source.Kernel.TcpIpSendIPV6 += d => CountBytes(d.ProcessID, d.size, incoming: false);
            _session.Source.Kernel.UdpIpRecvIPV6 += d => CountBytes(d.ProcessID, d.size, incoming: true);
            _session.Source.Kernel.UdpIpSendIPV6 += d => CountBytes(d.ProcessID, d.size, incoming: false);

            _pump = new Thread(Pump)
            {
                IsBackground = true,
                Name = "etw-process-watch",
            };
            _pump.Start();

            State = EtwState.Running;
            Error = null;
            return true;
        }
        catch (UnauthorizedAccessException)
        {
            State = EtwState.NeedsElevation;
            Error = "التقاط الأحداث اللحظية يحتاج صلاحية المدير";
            return false;
        }
        catch (Exception ex)
        {
            State = EtwState.Unavailable;
            Error = ex.Message;
            Dispose();
            return false;
        }
    }

    private void Pump()
    {
        try { _session?.Source.Process(); }
        catch when (_stopping) { /* torn down while blocked in Process() */ }
        catch (Exception ex)
        {
            State = EtwState.Unavailable;
            Error = ex.Message;
        }
    }

    private void OnProcessStart(ProcessTraceData data)
    {
        try
        {
            PayloadFields ??= string.Join(", ", data.PayloadNames);

            int pid = data.ProcessID;
            int ppid = data.ParentID;
            string image = data.ImageFileName ?? "";
            string name = image.Length > 0 ? image[(image.LastIndexOf('\\') + 1)..] : $"pid {pid}";

            string? parentName;
            lock (_namesLock)
            {
                _names[pid] = name;
                _names.TryGetValue(ppid, out parentName);
            }

            string? commandLine = string.IsNullOrWhiteSpace(data.CommandLine) ? null : data.CommandLine.Trim();

            string? path = ResolvePath(image, commandLine, pid);

            Started?.Invoke(new ProcessStart(
                data.TimeStamp.ToUniversalTime(), pid, ppid, name, path, commandLine,
                parentName ?? ResolveParentName(ppid)));
        }
        catch { /* a malformed event must never take the session down */ }
    }

    /// <summary>
    /// Works out where the image actually lives.
    ///
    /// The kernel event gives the image as an NT path on some builds and as a bare file name
    /// on others, and asking the process itself only works while it is still alive — which,
    /// for exactly the processes worth catching, it usually is not. The command line almost
    /// always opens with the full path, so that is the most reliable source, with the live
    /// query as a last resort.
    /// </summary>
    private static string? ResolvePath(string image, string? commandLine, int pid)
    {
        if (image.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
        {
            string? dos = NtPath.ToDosPath(image);
            if (dos is not null && !dos.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
                return dos;
        }
        else if (Path.IsPathRooted(image))
        {
            return image;
        }

        if (FirstToken(commandLine) is { Length: > 0 } fromCommand)
        {
            // "\??\C:\Windows\..." is the native form of a normal path.
            if (fromCommand.StartsWith(@"\??\", StringComparison.Ordinal)) fromCommand = fromCommand[4..];
            if (Path.IsPathRooted(fromCommand)) return fromCommand;
        }

        return Native.ProcessDetails.GetImagePath(pid) ?? (image.Length > 0 ? image : null);
    }

    /// <summary>The executable out of a command line — quoted, or up to the first space.</summary>
    private static string? FirstToken(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return null;
        var cl = commandLine.Trim();
        if (cl[0] == '"')
        {
            int close = cl.IndexOf('"', 1);
            return close > 1 ? cl[1..close] : null;
        }
        int space = cl.IndexOf(' ');
        return space < 0 ? cl : cl[..space];
    }

    /// <summary>Falls back to asking the OS when the parent started before we did.</summary>
    private static string? ResolveParentName(int pid)
    {
        try
        {
            using var p = System.Diagnostics.Process.GetProcessById(pid);
            return p.ProcessName + ".exe";
        }
        catch { return null; }
    }

    private static bool IsElevated()
    {
        try
        {
            using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
            return new System.Security.Principal.WindowsPrincipal(id)
                .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    public void Dispose()
    {
        _stopping = true;
        try { _session?.Stop(); } catch { }
        try { _session?.Dispose(); } catch { }
        _session = null;
        if (State == EtwState.Running) State = EtwState.Stopped;
    }
}
