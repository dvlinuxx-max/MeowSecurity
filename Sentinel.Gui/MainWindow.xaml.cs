using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Threading;
using Sentinel.Core.Live;
using Sentinel.Core.Processes;

namespace Sentinel.Gui;

public partial class MainWindow : Window
{
    private readonly ObservableCollection<LiveRow> _rows = [];
    private readonly Dictionary<int, LiveRow> _byPid = [];
    private readonly LiveSampler _sampler = new();
    private readonly LiveEnricher _enricher = new();
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(1) };

    private ListCollectionView _threatsView = null!;
    private ListCollectionView _netView = null!;

    private double _netMax = 64 * 1024;
    private bool _paused;

    public MainWindow()
    {
        InitializeComponent();

        Grid.ItemsSource = _rows;
        _threatsView = new ListCollectionView(_rows) { Filter = o => o is LiveRow r && r.IsFlagged };
        _netView = new ListCollectionView(_rows) { Filter = o => o is LiveRow r && r.RemoteConns > 0 };
        ThreatGrid.ItemsSource = _threatsView;
        AttentionList.ItemsSource = _threatsView;
        NetGrid.ItemsSource = _netView;

        NetSpark.Stroke = Res("NetIn"); NetSpark.Fill = Res("NetFill");
        NetBigGraph.Stroke = Res("NetIn"); NetBigGraph.Fill = Res("NetFill");
        HeroPulse.Stroke = Res("Green");

        ShowPage("overview");
        Loaded += (_, _) => { Tick(); _timer.Tick += (_, _) => Tick(); _timer.Start(); };
    }

    // ---------------- navigation ----------------

    private void OnNav(object sender, RoutedEventArgs e)
    {
        // Checked fires during InitializeComponent before the page grids exist.
        if (PageOverview is null) return;
        if (sender is RadioButton { Tag: string tag }) ShowPage(tag);
    }

    private void ShowPage(string tag)
    {
        PageOverview.Visibility = tag == "overview" ? Visibility.Visible : Visibility.Collapsed;
        PageProcesses.Visibility = tag == "processes" ? Visibility.Visible : Visibility.Collapsed;
        PageNetwork.Visibility = tag == "network" ? Visibility.Visible : Visibility.Collapsed;
        PageAutoruns.Visibility = tag == "autoruns" ? Visibility.Visible : Visibility.Collapsed;
        PageThreats.Visibility = tag == "threats" ? Visibility.Visible : Visibility.Collapsed;

        // First time the autoruns page is opened, scan automatically.
        if (tag == "autoruns" && !_autorunsScanned) ScanAutoruns();
    }

    // ---------------- autoruns ----------------

    private readonly ObservableCollection<AutorunRow> _autoruns = [];
    private bool _autorunsScanned;
    private bool _autorunsScanning;

    private void OnScanAutoruns(object sender, RoutedEventArgs e) => ScanAutoruns();

    private async void ScanAutoruns()
    {
        if (_autorunsScanning) return;
        _autorunsScanning = true;
        _autorunsScanned = true;
        AutorunScanBtn.IsEnabled = false;
        AutorunSummary.Text = "جارٍ الفحص…";
        AutorunHint.Visibility = Visibility.Collapsed;

        var scanner = new Sentinel.Core.Persistence.AutorunScanner();
        var entries = await Task.Run(() => scanner.Scan());

        _autoruns.Clear();
        int flagged = 0;
        foreach (var entry in entries
                     .OrderByDescending(x => (int)x.Verdict)
                     .ThenBy(x => x.Location))
        {
            var row = new AutorunRow(entry);
            if (row.IsFlagged) flagged++;
            _autoruns.Add(row);
        }

        AutorunGrid.ItemsSource = _autoruns;
        AutorunSummary.Text = flagged > 0
            ? $"{_autoruns.Count} عنصر · {flagged} يحتاج مراجعة"
            : $"{_autoruns.Count} عنصر · كلها سليمة";
        AutorunScanBtn.IsEnabled = true;
        AutorunScanBtn.Content = "إعادة الفحص";
        _autorunsScanning = false;
    }

    // ---------------- live loop ----------------

    private void Tick()
    {
        if (_paused) return;

        var sample = _sampler.Sample(out var pulse);
        _enricher.Overlay(sample);

        var seen = new HashSet<int>(sample.Count);
        int suspicious = 0, review = 0, hidden = 0;

        foreach (var p in sample)
        {
            seen.Add(p.Pid);
            if (p.Verdict == Verdict.Suspicious) suspicious++;
            else if (p.Verdict == Verdict.Review) review++;
            if (p.IsHidden) hidden++;

            if (_byPid.TryGetValue(p.Pid, out var row))
            {
                row.Update(p);
                row.TickHighlight();
            }
            else
            {
                var fresh = new LiveRow(p);
                fresh.MarkNew();
                _byPid[p.Pid] = fresh;
                _rows.Add(fresh);
            }
        }

        for (int i = _rows.Count - 1; i >= 0; i--)
        {
            if (!seen.Contains(_rows[i].Pid))
            {
                _byPid.Remove(_rows[i].Pid);
                _rows.RemoveAt(i);
            }
        }

        UpdateReadouts(pulse);
        UpdateVerdict(suspicious, review, hidden);

        _threatsView.Refresh();
        _netView.Refresh();
        if (!string.IsNullOrEmpty(Search.Text))
            CollectionViewSource.GetDefaultView(_rows)?.Refresh();

        _enricher.EnrichMissing(sample, scanMemory: true);
    }

    private void UpdateReadouts(SystemPulse pulse)
    {
        CpuBig.Text = $"{pulse.CpuPercent:0}%";
        CpuMeter.Value = pulse.CpuPercent;
        HeroPulse.Push(pulse.CpuPercent / 100.0);

        double memFrac = pulse.MemoryTotal > 0 ? (double)pulse.MemoryUsed / pulse.MemoryTotal : 0;
        MemBig.Text = $"{memFrac * 100:0}%";
        MemMeter.Value = memFrac * 100;
        MemDetail.Text = $"{Bytes(pulse.MemoryUsed)} / {Bytes(pulse.MemoryTotal)}";

        long net = Math.Max(pulse.NetInBytesPerSec, pulse.NetOutBytesPerSec);
        _netMax = Math.Max(net, _netMax * 0.9);
        if (_netMax < 64 * 1024) _netMax = 64 * 1024;
        string down = $"↓ {Rate(pulse.NetInBytesPerSec)}", up = $"↑ {Rate(pulse.NetOutBytesPerSec)}";
        NetDown.Text = down; NetUp.Text = up;
        NetDownBig.Text = down; NetUpBig.Text = up;
        double frac = net / _netMax;
        NetSpark.Push(frac); NetBigGraph.Push(frac);

        ProcBig.Text = pulse.ProcessCount.ToString();
        ThreadSub.Text = $"{pulse.ThreadCount} خيط";
    }

    private void UpdateVerdict(int suspicious, int review, int hidden)
    {
        int flagged = _threatsView.Count;
        AttentionEmpty.Visibility = flagged > 0 ? Visibility.Collapsed : Visibility.Visible;
        ThreatsEmpty.Visibility = flagged > 0 ? Visibility.Collapsed : Visibility.Visible;

        Brush color;
        int alarm = suspicious + hidden;
        if (alarm > 0)
        {
            color = Res("Red");
            HeroTitle.Text = $"انتبه — {alarm} عنصر يحتاج تدقيقاً";
            HeroSub.Text = "افتح صفحة التهديدات لمراجعة العناصر الحمراء";
        }
        else if (review > 0)
        {
            color = Res("Amber");
            HeroTitle.Text = "جهازك سليم، مع عناصر للمراجعة";
            HeroSub.Text = $"{review} عنصر بلا توقيع خارج مجلدات النظام — غالباً عادي";
        }
        else
        {
            color = Res("Green");
            HeroTitle.Text = "جهازك سليم";
            HeroSub.Text = "كل العمليات موقّعة، ولا كود محقون، ولا عملية مخفية";
        }
        HeroTitle.Foreground = color;
        HeroPulse.Stroke = color;
        LiveDot.Fill = color;
    }

    // ---------------- toolbar ----------------

    private void OnPauseToggle(object sender, RoutedEventArgs e)
    {
        _paused = !_paused;
        PauseButton.Content = _paused ? "استئناف" : "إيقاف مؤقّت";
        LiveLabel.Text = _paused ? "المراقبة موقوفة" : "المراقبة نشطة";
    }

    // ---------------- process actions (context menu) ----------------

    private static LiveRow? RowFrom(object sender)
    {
        if (sender is MenuItem { Parent: ContextMenu { PlacementTarget: DataGrid dg } })
            return dg.SelectedItem as LiveRow;
        return null;
    }

    private void OnSuspendProcess(object sender, RoutedEventArgs e)
    {
        if (RowFrom(sender) is { } r && !Sentinel.Core.Native.ProcessControl.Suspend(r.Pid))
            MessageBox.Show(this, "تعذّر الإيقاف — قد تكون عملية محمية.", "تنبيه",
                MessageBoxButton.OK, MessageBoxImage.Warning);
    }

    private void OnResumeProcess(object sender, RoutedEventArgs e)
    {
        if (RowFrom(sender) is { } r) Sentinel.Core.Native.ProcessControl.Resume(r.Pid);
    }

    private void OnKillProcess(object sender, RoutedEventArgs e)
    {
        if (RowFrom(sender) is not { } r) return;
        var ask = MessageBox.Show(this,
            $"إنهاء \"{r.Name}\" (PID {r.Pid})؟\n\nإنهاء عملية نظام قد يجعل الجهاز غير مستقر حتى إعادة التشغيل.",
            "تأكيد الإنهاء", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (ask != MessageBoxResult.Yes) return;
        try
        {
            using var p = System.Diagnostics.Process.GetProcessById(r.Pid);
            p.Kill();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"تعذّر الإنهاء: {ex.Message}", "خطأ",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void OnOpenLocation(object sender, RoutedEventArgs e)
    {
        if (RowFrom(sender) is not { ImagePath: { Length: > 0 } path }) return;
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("explorer.exe",
                $"/select,\"{path}\"") { UseShellExecute = true });
        }
        catch { /* path gone or access denied */ }
    }

    private void OnCopyName(object sender, RoutedEventArgs e)
    {
        if (RowFrom(sender) is not { } r) return;
        try { Clipboard.SetText($"{r.Name} (PID {r.Pid})"); } catch { }
    }

    private void OnSearchChanged(object sender, RoutedEventArgs e)
    {
        SearchHint.Visibility = string.IsNullOrEmpty(Search.Text)
            ? Visibility.Visible : Visibility.Collapsed;
        var view = CollectionViewSource.GetDefaultView(_rows);
        if (view is null) return;
        string q = Search.Text.Trim();
        view.Filter = q.Length == 0 ? null : o =>
            o is LiveRow r &&
            (r.Name.Contains(q, StringComparison.OrdinalIgnoreCase) || r.Pid.ToString().Contains(q));
    }

    private static Brush Res(string key) => (Brush)App.Current.Resources[key];

    private static string Bytes(long b)
    {
        if (b <= 0) return "0";
        string[] u = { "ب", "ك", "م", "غ", "ت" };
        double v = b; int i = 0;
        while (v >= 1024 && i < u.Length - 1) { v /= 1024; i++; }
        return $"{v:0.#} {u[i]}";
    }

    private static string Rate(long bps)
    {
        if (bps <= 0) return "0";
        string[] u = { "ب/ث", "ك/ث", "م/ث", "غ/ث" };
        double v = bps; int i = 0;
        while (v >= 1024 && i < u.Length - 1) { v /= 1024; i++; }
        return $"{v:0.#} {u[i]}";
    }
}
