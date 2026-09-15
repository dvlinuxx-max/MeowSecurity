using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Media;
using Sentinel.Core.Live;
using Sentinel.Core.Processes;

namespace Sentinel.Gui;

/// <summary>
/// One grid row, updated in place each tick. Implements INotifyPropertyChanged so the moving
/// numbers (CPU, memory, I/O, network) refresh without rebuilding the list — the whole point
/// of a live monitor.
/// </summary>
public sealed class LiveRow : INotifyPropertyChanged
{
    public int Pid { get; }
    public string? ImagePath { get; private set; }
    public string? CommandLine { get; private set; }
    public LiveRow(LiveProcess p) { Pid = p.Pid; Update(p); }

    /// <summary>Hover detail: full image path and the command line it was launched with.</summary>
    public string Tooltip =>
        string.IsNullOrEmpty(CommandLine)
            ? (string.IsNullOrEmpty(ImagePath) ? Name : ImagePath)
            : $"{ImagePath}\n\n{CommandLine}";

    private string _name = "";
    private double _cpuValue;
    private string _cpu = "";
    private long _privateBytes;
    private string _privateText = "";
    private string _workingText = "";
    private int _threads;
    private string _io = "";
    private long _ioValue;
    private string _network = "";
    private int _remoteConns;
    private string _signature = "";
    private string _publisher = "";
    private string _reasons = "";
    private Verdict _verdict;
    private ProcessKind _kind;
    private int _highlightTicks;

    public string Name { get => _name; private set => Set(ref _name, value); }
    public double CpuValue { get => _cpuValue; private set => Set(ref _cpuValue, value); }
    public string Cpu { get => _cpu; private set => Set(ref _cpu, value); }
    public long PrivateBytes { get => _privateBytes; private set => Set(ref _privateBytes, value); }
    public string PrivateText { get => _privateText; private set => Set(ref _privateText, value); }
    public string WorkingText { get => _workingText; private set => Set(ref _workingText, value); }
    public int Threads { get => _threads; private set => Set(ref _threads, value); }
    public string Io { get => _io; private set => Set(ref _io, value); }
    public long IoValue { get => _ioValue; private set => Set(ref _ioValue, value); }
    public string Network { get => _network; private set => Set(ref _network, value); }
    public int RemoteConns { get => _remoteConns; private set => Set(ref _remoteConns, value); }
    public string Signature { get => _signature; private set => Set(ref _signature, value); }
    public string Publisher { get => _publisher; private set => Set(ref _publisher, value); }
    public string Reasons { get => _reasons; private set => Set(ref _reasons, value); }

    public Verdict Verdict
    {
        get => _verdict;
        private set
        {
            if (Set(ref _verdict, value))
            {
                Notify(nameof(VerdictText));
                Notify(nameof(Accent));
                Notify(nameof(Tint));
                Notify(nameof(IsFlagged));
            }
        }
    }

    public ProcessKind Kind
    {
        get => _kind;
        private set { if (Set(ref _kind, value)) Notify(nameof(NameColor)); }
    }

    public bool IsFlagged => _verdict != Verdict.Safe;

    public string VerdictText => _verdict switch
    {
        Verdict.Suspicious => "مشبوه",
        Verdict.Review => "راجعه",
        _ => "آمن",
    };

    public Brush Accent => _verdict switch
    {
        Verdict.Suspicious => Res("Red"),
        Verdict.Review => Res("Amber"),
        _ => Res("Green"),
    };

    public Brush Tint => _verdict switch
    {
        Verdict.Suspicious => Res("RedTint"),
        Verdict.Review => Res("AmberTint"),
        _ => Res("GreenTint"),
    };

    // Process-type colouring, task-monitor style: services and own process stand out.
    public Brush NameColor => _kind switch
    {
        ProcessKind.Own => Res("Brand"),
        ProcessKind.Service => Res("ServiceText"),
        ProcessKind.System => Res("Muted"),
        _ => Res("Text"),
    };

    // Fades over a couple of ticks after a process first appears.
    public Brush RowHighlight => _highlightTicks > 0 ? Res("NewTint") : Brushes.Transparent;

    public void Update(LiveProcess p)
    {
        ImagePath = p.ImagePath;
        CommandLine = p.CommandLine;
        Name = p.Name;
        CpuValue = p.CpuPercent;
        Cpu = p.CpuPercent < 0.05 ? "" : p.CpuPercent.ToString("0.0");
        PrivateBytes = p.PrivateBytes;
        PrivateText = Bytes(p.PrivateBytes);
        WorkingText = Bytes(p.WorkingSet);
        Threads = p.Threads;
        IoValue = p.IoBytesPerSec;
        Io = p.IoBytesPerSec > 0 ? Rate(p.IoBytesPerSec) : "";
        RemoteConns = p.RemoteConnections;
        Network = p.RemoteConnections > 0 ? $"{p.RemoteConnections} اتصال"
                : p.Connections > 0 ? $"{p.Connections} منفذ" : "";
        Signature = p.Signature switch
        {
            SignatureState.SignedValid => "موقّع",
            SignatureState.SignedInvalid => "غير صالح",
            SignatureState.Unsigned => "غير موقّع",
            _ => "",
        };
        Publisher = p.Publisher ?? p.Description ?? "";
        Reasons = string.Join("، ", p.Reasons);
        Kind = p.Kind;
        Verdict = p.Verdict;
        Notify(nameof(Tooltip));
    }

    public void MarkNew() { _highlightTicks = 2; Notify(nameof(RowHighlight)); }

    public void TickHighlight()
    {
        if (_highlightTicks > 0 && --_highlightTicks == 0)
            Notify(nameof(RowHighlight));
    }

    private static Brush Res(string key) => (Brush)App.Current.Resources[key];

    private static string Bytes(long b)
    {
        if (b <= 0) return "";
        string[] u = { "ب", "ك", "م", "غ", "ت" };
        double v = b; int i = 0;
        while (v >= 1024 && i < u.Length - 1) { v /= 1024; i++; }
        return $"{v:0.#} {u[i]}";
    }

    private static string Rate(long bps)
    {
        if (bps <= 0) return "";
        string[] u = { "ب/ث", "ك/ث", "م/ث", "غ/ث" };
        double v = bps; int i = 0;
        while (v >= 1024 && i < u.Length - 1) { v /= 1024; i++; }
        return $"{v:0.#} {u[i]}";
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void Notify([CallerMemberName] string? n = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(n));
    private bool Set<T>(ref T field, T value, [CallerMemberName] string? n = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        Notify(n);
        return true;
    }
}
