using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Threading;
using Sentinel.Core.Detect;
using Sentinel.Core.Intel;
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

    private readonly IntelSettings _settings = IntelSettings.Load();
    private ThreatIntel _intel = null!;
    private ReputationService _reputation = null!;
    private bool _loadingSettings;

    private readonly HashSet<int> _alerted = [];
    private readonly DispatcherTimer _toastTimer = new() { Interval = TimeSpan.FromSeconds(9) };

    private TrayIcon? _tray;
    private bool _exiting;
    private bool _toldUserAboutTray;

    private readonly EventStore _events = new();
    private readonly BehaviorWatcher _watcher;
    private readonly Sentinel.Core.Etw.ProcessStartWatcher _etw = new();
    private readonly ObservableCollection<EventRow> _eventRows = [];
    private ListCollectionView _eventsView = null!;

    private ListCollectionView _threatsView = null!;
    private ListCollectionView _netView = null!;

    private double _netMax = 64 * 1024;
    private bool _paused;

    public MainWindow()
    {
        _watcher = new BehaviorWatcher(_events);

        InitializeComponent();

        Grid.ItemsSource = _rows;
        LoadEventHistory();
        _threatsView = new ListCollectionView(_rows) { Filter = o => o is LiveRow r && r.IsFlagged };
        _netView = new ListCollectionView(_rows) { Filter = o => o is LiveRow r && r.RemoteConns > 0 };
        ThreatGrid.ItemsSource = _threatsView;
        AttentionList.ItemsSource = _threatsView;
        NetGrid.ItemsSource = _netView;

        NetSpark.Stroke = Res("NetIn"); NetSpark.Fill = Res("NetFill");
        NetBigGraph.Stroke = Res("NetIn"); NetBigGraph.Fill = Res("NetFill");

        _intel = new ThreatIntel(_settings);
        _reputation = new ReputationService(_intel, Dispatcher, OnFlaggedByReputation);
        _toastTimer.Tick += (_, _) => HideToast();
        LoadSettingsUi();

        // Read the version off the assembly so the about card can never drift from the build.
        var v = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
        AboutVersion.Text = $"الإصدار {v?.Major ?? 0}.{v?.Minor ?? 1}  ·  رخصة GPL-3.0";

        ShowPage("overview");
        Loaded += (_, _) =>
        {
            Tick();
            _timer.Tick += (_, _) => Tick();
            _timer.Start();
            StartLiveCapture();
            // Present from the start: a monitor that is running should say so, and an alert
            // cannot reach the notification area without it.
            if (_settings.SystemNotifications) EnsureTray();
        };
        Closing += OnClosing;
        Closed += (_, _) => { _reputation.Dispose(); _intel.Dispose(); _tray?.Dispose(); _etw.Dispose(); };
    }

    // ---------------- settings ----------------

    private void LoadSettingsUi()
    {
        _loadingSettings = true;
        ChkLight.IsChecked = string.Equals(_settings.Theme, "light", StringComparison.OrdinalIgnoreCase);
        ChkNotify.IsChecked = _settings.Notifications;
        ChkSystemNotify.IsChecked = _settings.SystemNotifications;
        ChkSound.IsChecked = _settings.AlertSound;
        ChkBackground.IsChecked = _settings.RunInBackground;
        ChkHealth.IsChecked = _settings.HealthMonitoring;
        if (!string.IsNullOrEmpty(_settings.VirusTotalApiKey)) KeyVt.Password = _settings.VirusTotalApiKey;
        if (!string.IsNullOrEmpty(_settings.AbuseIpdbApiKey)) KeyAbuseIpdb.Password = _settings.AbuseIpdbApiKey;
        if (!string.IsNullOrEmpty(_settings.AbuseChApiKey)) KeyAbuseCh.Password = _settings.AbuseChApiKey;
        _loadingSettings = false;

        if (IsElevated())
        {
            ElevateStatus.Text = "يعمل بصلاحية المدير — رؤية كاملة لكل العمليات";
            ElevateBtn.Visibility = Visibility.Collapsed;
        }
        else
        {
            ElevateStatus.Text = "بعض عمليات النظام مخفية بدون صلاحية المدير";
            ElevateBtn.Visibility = Visibility.Visible;
        }
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

    private void OnElevate(object sender, RoutedEventArgs e)
    {
        try
        {
            var exe = Environment.ProcessPath;
            if (exe is null) return;
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(exe)
            {
                Verb = "runas",
                UseShellExecute = true,
            });
            Application.Current.Shutdown();
        }
        catch { /* user declined the UAC prompt */ }
    }

    private void OnThemeToggle(object sender, RoutedEventArgs e)
    {
        if (_loadingSettings) return;
        _settings.Theme = ChkLight.IsChecked == true ? "light" : "dark";
        _settings.Save();

        // Re-colour the palette and rebuild the window so every StaticResource picks up
        // the new theme (WPF freezes resource brushes, so they can't be recoloured in place).
        ThemeManager.Apply(_settings.Theme);
        var fresh = new MainWindow();
        fresh.Show();
        fresh.NavSettings.IsChecked = true;
        _timer.Stop();
        Close(); // the Closed handler disposes intel + reputation
    }

    private void OnPrefChanged(object sender, RoutedEventArgs e)
    {
        if (_loadingSettings) return;
        _settings.Notifications = ChkNotify.IsChecked == true;
        _settings.SystemNotifications = ChkSystemNotify.IsChecked == true;
        _settings.AlertSound = ChkSound.IsChecked == true;
        if (_settings.SystemNotifications) EnsureTray();
        _settings.RunInBackground = ChkBackground.IsChecked == true;
        _settings.HealthMonitoring = ChkHealth.IsChecked == true;
        _settings.Save();
    }

    private void OnSaveKeys(object sender, RoutedEventArgs e)
    {
        _settings.VirusTotalApiKey = Nz(KeyVt.Password);
        _settings.AbuseIpdbApiKey = Nz(KeyAbuseIpdb.Password);
        _settings.AbuseChApiKey = Nz(KeyAbuseCh.Password);
        _settings.VirusTotalEnabled = !string.IsNullOrWhiteSpace(_settings.VirusTotalApiKey);
        _settings.Save();

        _intel.Dispose();
        _intel = new ThreatIntel(_settings);
        KeysStatus.Text = "تم الحفظ ✓";
    }

    private static string? Nz(string s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();

    // ---------------- advanced scan ----------------

    private string? _scanLink;

    private void OnScanInputChanged(object sender, RoutedEventArgs e) =>
        ScanHint.Visibility = string.IsNullOrEmpty(ScanInput.Text) ? Visibility.Visible : Visibility.Collapsed;

    private void OnScanInputKey(object sender, System.Windows.Input.KeyEventArgs e)
    {
        if (e.Key == System.Windows.Input.Key.Enter) OnAdvancedScan(sender, e);
    }

    private async void OnAdvancedScan(object sender, RoutedEventArgs e)
    {
        var input = ScanInput.Text?.Trim();
        if (string.IsNullOrEmpty(input)) return;

        ScanBtn.IsEnabled = false;
        ShowScanResult(ThreatLevel.Unknown, "جاري الفحص…", input, "قد يستغرق حتى دقيقة للروابط الجديدة.", null);

        ScanReport r;
        try { r = await _intel.AdvancedScanAsync(input); }
        catch (Exception ex) { r = new ScanReport { Target = input, Error = ex.Message }; }

        ScanBtn.IsEnabled = true;
        if (!r.Ok) { ShowScanResult(ThreatLevel.Suspicious, "تعذر الفحص", input, r.Error!, null); return; }

        string verdict = r.Level switch
        {
            ThreatLevel.Malicious => "خبيث",
            ThreatLevel.Suspicious => "مشبوه",
            ThreatLevel.KnownGood => "نظيف",
            _ => "غير معروف",
        };
        ShowScanResult(r.Level, verdict, r.Target, r.Detail ?? "", r.Permalink);
    }

    private void ShowScanResult(ThreatLevel level, string verdict, string target, string detail, string? link)
    {
        var (accent, tint) = level switch
        {
            ThreatLevel.Malicious => (Res("Red"), Res("RedTint")),
            ThreatLevel.Suspicious => (Res("Amber"), Res("AmberTint")),
            ThreatLevel.KnownGood => (Res("Green"), Res("GreenTint")),
            _ => (Res("Muted"), Res("CardAlt")),
        };
        ScanResult.Tag = tint;
        ScanDot.Fill = accent;
        ScanVerdict.Text = verdict;
        ScanVerdict.Foreground = accent;
        ScanTarget.Text = target;
        ScanDetail.Text = detail;
        _scanLink = link;
        ScanLink.Text = link is null ? "" : "عرض التقرير الكامل ↗";
        ScanLink.Visibility = link is null ? Visibility.Collapsed : Visibility.Visible;
        ScanResult.Visibility = Visibility.Visible;
    }

    private void OnScanLinkClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (string.IsNullOrEmpty(_scanLink)) return;
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(_scanLink) { UseShellExecute = true });
        }
        catch { /* no browser or blocked */ }
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
        PageEvents.Visibility = tag == "events" ? Visibility.Visible : Visibility.Collapsed;
        PageAlerts.Visibility = tag == "alerts" ? Visibility.Visible : Visibility.Collapsed;
        PageSettings.Visibility = tag == "settings" ? Visibility.Visible : Visibility.Collapsed;

        // First time the autoruns page is opened, scan automatically.
        if (tag == "autoruns" && !_autorunsScanned) ScanAutoruns();
    }

    // ---------------- background monitoring ----------------

    /// <summary>
    /// Closing the window is not the same as quitting. With background monitoring on, the
    /// window goes away and the engine keeps running behind a tray icon — which is the only
    /// arrangement under which the event log is worth anything, since the interesting things
    /// happen while nobody is looking at the screen.
    /// </summary>
    private void OnClosing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        if (_exiting || !_settings.RunInBackground) return;

        EnsureTray();
        if (_tray?.IsVisible != true)
        {
            // The shell refused the icon. Hiding now would strand a running monitor with no
            // way back to it, so close for real instead.
            _tray?.Dispose();
            _tray = null;
            return;
        }

        e.Cancel = true;
        Hide();

        // Say it once. A tray icon that swallows the window without a word feels like a bug.
        if (!_toldUserAboutTray)
        {
            _toldUserAboutTray = true;
            _tray?.Notify("Meow Security ما زال يراقب",
                "المراقبة تعمل في الخلفية. انقر الأيقونة للعودة، أو أوقفها من قائمة اليمين.", serious: false);
        }
    }

    private void EnsureTray()
    {
        if (_tray is not null) return;

        _tray = new TrayIcon("Meow Security — المراقبة تعمل");
        _tray.Activated += RestoreFromTray;
        _tray.ContextMenuRequested += ShowTrayMenu;
    }

    private void RestoreFromTray()
    {
        Show();
        WindowState = WindowState.Normal;
        Activate();
    }

    private void ShowTrayMenu()
    {
        _tray?.PrepareForMenu();

        var menu = new ContextMenu { Placement = System.Windows.Controls.Primitives.PlacementMode.MousePoint };
        menu.Items.Add(Item("فتح Sentinel", RestoreFromTray));
        menu.Items.Add(Item(_paused ? "استئناف المراقبة" : "إيقاف المراقبة مؤقتا", () =>
        {
            OnPauseToggle(this, new RoutedEventArgs());
            _tray?.UpdateTip(_paused ? "Meow Security — المراقبة متوقفة" : "Meow Security — المراقبة تعمل");
        }));
        menu.Items.Add(new Separator());
        menu.Items.Add(Item("خروج", ExitApp));
        menu.IsOpen = true;

        static MenuItem Item(string header, Action onClick)
        {
            var item = new MenuItem { Header = header };
            item.Click += (_, _) => onClick();
            return item;
        }
    }

    private void ExitApp()
    {
        _exiting = true;
        _timer.Stop();
        _tray?.Dispose();
        _tray = null;
        Close();
        Application.Current.Shutdown();
    }

    // ---------------- live capture (ETW) ----------------

    /// <summary>
    /// Judges every process the moment the kernel creates it.
    ///
    /// The one-second poll can only see what is still alive when it looks, and the processes
    /// worth catching are precisely the ones that are not: an encoded PowerShell one-liner
    /// runs and exits in a few hundred milliseconds. This closes that window. It needs
    /// administrator rights; without them the poll still runs and the settings page says why.
    /// </summary>
    private void StartLiveCapture()
    {
        _etw.Started += OnProcessStarted;
        _etw.Start();
        UpdateCaptureStatus();
    }

    private void UpdateCaptureStatus()
    {
        if (CaptureStatus is null) return;
        CaptureStatus.Text = _etw.State switch
        {
            Sentinel.Core.Etw.EtwState.Running => "الالتقاط اللحظي يعمل — يفحص كل عملية لحظة إنشائها",
            Sentinel.Core.Etw.EtwState.NeedsElevation =>
                "الالتقاط اللحظي متوقف — يحتاج صلاحية المدير. بدونه قد تفوت عمليات تعيش أقل من ثانية.",
            _ => $"الالتقاط اللحظي غير متاح: {_etw.Error}",
        };
        CaptureStatus.Foreground = Res(_etw.State == Sentinel.Core.Etw.EtwState.Running ? "Green" : "Muted");
    }

    /// <summary>Arrives on an ETW thread, so everything touching the UI hops to the dispatcher.</summary>
    private void OnProcessStarted(Sentinel.Core.Etw.ProcessStart p)
    {
        if (_paused) return;

        var ctx = new ProcessContext(
            p.Pid, p.Name, p.ParentPid, p.ParentName,
            p.ImagePath, p.CommandLine,
            // Verifying a signature here would block the ETW callback; the polling pass does
            // it a moment later. What this catches is behaviour, which needs no file access.
            SignatureState.Unknown,
            IsHidden: false, HasImplantedPe: false, RemoteConnections: 0, SessionId: 0);

        var ev = _watcher.InspectOne(ctx);
        if (ev is null) return;

        Dispatcher.BeginInvoke(() => RecordEvents([ev]));
    }

    // ---------------- alerts (what to do about it) ----------------

    private readonly ObservableCollection<AlertCard> _alerts = [];

    /// <summary>
    /// Only findings worth interrupting someone over reach this page. Everything else stays
    /// in the events log, where it belongs.
    /// </summary>
    private void AddAlert(SecurityEvent ev)
    {
        if (ev.Severity < Severity.Medium) return;

        _alerts.Insert(0, new AlertCard(ev));
        while (_alerts.Count > 50) _alerts.RemoveAt(_alerts.Count - 1);
        UpdateAlertsUi();
    }

    private void UpdateAlertsUi()
    {
        if (AlertSummary is null) return;

        AlertList.ItemsSource = _alerts;
        int serious = _alerts.Count(a => a.Event.Severity >= Severity.High);
        AlertSummary.Text = _alerts.Count == 0
            ? "لا تنبيهات"
            : $"{_alerts.Count} تنبيه · {serious} يحتاج تصرفا";
        AlertsEmpty.Visibility = _alerts.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        AlertBadge.Visibility = serious > 0 ? Visibility.Visible : Visibility.Collapsed;
        AlertBadgeText.Text = serious > 99 ? "99+" : serious.ToString();
    }

    private void OnClearAlerts(object sender, RoutedEventArgs e)
    {
        _alerts.Clear();
        UpdateAlertsUi();
    }

    private static AlertCard? CardFrom(object sender) =>
        (sender as FrameworkElement)?.Tag as AlertCard;

    private void OnAlertLocate(object sender, RoutedEventArgs e)
    {
        var path = CardFrom(sender)?.Event.ImagePath;
        if (string.IsNullOrEmpty(path)) return;
        try
        {
            if (System.IO.File.Exists(path))
                System.Diagnostics.Process.Start("explorer.exe", $"/select,\"{path}\"");
            else
                MessageBox.Show("الملف لم يعد موجودا في مساره.", "Meow Security",
                    MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch { }
    }

    private void OnAlertKill(object sender, RoutedEventArgs e)
    {
        var card = CardFrom(sender);
        if (card is null) return;

        if (MessageBox.Show($"إنهاء {card.Event.Process} (رقم {card.Event.Pid})؟\n\n" +
                            "إذا كان البرنامج يحفظ شيئا الآن فقد تفقده.",
                "تأكيد", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;

        try
        {
            using var p = System.Diagnostics.Process.GetProcessById(card.Event.Pid);
            p.Kill();
            AlertSummary.Text = $"أنهيت {card.Event.Process}";
        }
        catch (ArgumentException)
        {
            MessageBox.Show("العملية انتهت بالفعل.", "Meow Security",
                MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"تعذر إنهاء العملية: {ex.Message}\n\nجرب تشغيل البرنامج بصلاحية المدير.",
                "Meow Security", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void OnAlertScan(object sender, RoutedEventArgs e)
    {
        var path = CardFrom(sender)?.Event.ImagePath;
        if (string.IsNullOrEmpty(path)) return;

        NavThreats.IsChecked = true;
        ScanInput.Text = path;
        OnScanInputChanged(this, new RoutedEventArgs());
        OnAdvancedScan(this, new RoutedEventArgs());
    }

    // ---------------- security events ----------------

    /// <summary>
    /// Brings back what happened while the app was closed. This is the whole point of the
    /// events page: an attack at 03:00 is still on the screen at 09:00.
    /// </summary>
    private void LoadEventHistory()
    {
        foreach (var ev in _events.Load(500))   // already newest-first
        {
            _eventRows.Add(new EventRow(ev));
            if (ev.Severity >= Severity.Medium && _alerts.Count < 50) _alerts.Add(new AlertCard(ev));
        }
        UpdateAlertsUi();

        _eventsView = new ListCollectionView(_eventRows)
        {
            Filter = o => o is EventRow r &&
                          (EventOnlySerious?.IsChecked != true || r.Severity >= Severity.High),
        };
        EventGrid.ItemsSource = _eventsView;
        UpdateEventSummary();
    }

    private void RecordEvents(IReadOnlyList<SecurityEvent> fresh)
    {
        if (fresh.Count == 0) return;

        foreach (var ev in fresh)
        {
            _eventRows.Insert(0, new EventRow(ev));   // newest on top
            AddAlert(ev);
        }

        UpdateEventSummary();

        // Only the serious ones interrupt; the rest wait quietly in the log.
        var worst = fresh.OrderByDescending(e => e.Score).First();
        if (_settings.Notifications && worst.Severity >= _watcher.AlertFloor && _alerted.Add(worst.Pid))
            ShowAlert(worst.Title, worst.Detail,
                Res(worst.Severity == Severity.Critical ? "Red" : "Amber"));
    }

    private void UpdateEventSummary()
    {
        if (EventSummary is null) return;
        int serious = _eventRows.Count(r => r.Severity >= Severity.High);
        EventSummary.Text = _eventRows.Count == 0
            ? "لا أحداث"
            : $"{_eventRows.Count} حدث · {serious} خطير";
        EventHint.Visibility = _eventRows.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        EventBadge.Visibility = serious > 0 ? Visibility.Visible : Visibility.Collapsed;
        EventBadgeText.Text = serious > 99 ? "99+" : serious.ToString();
    }

    private void OnEventFilter(object sender, RoutedEventArgs e) => _eventsView?.Refresh();

    private void OnClearEvents(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show("حذف كل الأحداث المسجلة نهائيا؟", "مسح السجل",
                MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;

        _events.Clear();
        _eventRows.Clear();
        UpdateEventSummary();
    }

    // ---------------- autoruns ----------------

    private readonly ObservableCollection<AutorunRow> _autoruns = [];
    private ListCollectionView? _autorunsView;
    private bool _autorunsScanned;
    private bool _autorunsScanning;

    private void OnScanAutoruns(object sender, RoutedEventArgs e) => ScanAutoruns();

    private async void ScanAutoruns()
    {
        if (_autorunsScanning) return;
        _autorunsScanning = true;
        _autorunsScanned = true;
        AutorunScanBtn.IsEnabled = false;
        AutorunSummary.Text = "جاري الفحص…";
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

        _autorunsView = new ListCollectionView(_autoruns)
        {
            Filter = o => o is AutorunRow r && (AutorunShowSystem.IsChecked == true || !r.IsSystem),
        };
        AutorunGrid.ItemsSource = _autorunsView;
        UpdateAutorunSummary(flagged);

        AutorunScanBtn.IsEnabled = true;
        AutorunScanBtn.Content = "إعادة الفحص";
        _autorunsScanning = false;
    }

    private void UpdateAutorunSummary(int flagged)
    {
        int hidden = AutorunShowSystem.IsChecked == true ? 0 : _autoruns.Count(r => r.IsSystem);
        var parts = new List<string> { $"{_autoruns.Count - hidden} عنصر" };
        parts.Add(flagged > 0 ? $"{flagged} يحتاج مراجعة" : "كلها سليمة");
        if (hidden > 0) parts.Add($"{hidden} من مكونات ويندوز مخفية");
        AutorunSummary.Text = string.Join(" · ", parts);
    }

    /// <summary>
    /// Acting on an autorun, not just reporting it. Disabling uses the same store Windows and
    /// Task Manager use, so it is visible to the rest of the system and can be undone; removal
    /// is a separate, confirmed step that keeps a record of what it deleted.
    /// </summary>
    private AutorunRow? SelectedAutorun => AutorunGrid.SelectedItem as AutorunRow;

    /// <summary>
    /// A right-click in WPF does not select the row under the cursor, so a context menu opened
    /// that way would act on whatever happened to be selected before — or on nothing at all.
    /// </summary>
    private void OnAutorunRightClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        for (DependencyObject? d = e.OriginalSource as DependencyObject; d is not null;
             d = System.Windows.Media.VisualTreeHelper.GetParent(d))
        {
            if (d is DataGridRow row)
            {
                row.IsSelected = true;
                AutorunGrid.SelectedItem = row.Item;
                return;
            }
        }
    }

    private void OnAutorunSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        var row = SelectedAutorun;
        bool has = row is not null;

        AutorunLocateBtn.IsEnabled = has;
        AutorunToggleBtn.IsEnabled = has;
        AutorunRemoveBtn.IsEnabled = has &&
            row!.Entry.Kind is Sentinel.Core.Persistence.AutorunKind.RunKey
                            or Sentinel.Core.Persistence.AutorunKind.StartupFolder;
        AutorunToggleBtn.Content = row?.Entry.Enabled == false ? "تفعيل" : "تعطيل";
    }

    private void OnAutorunMenuOpened(object sender, RoutedEventArgs e)
    {
        var row = SelectedAutorun;
        AutorunToggleItem.Header = row?.Entry.Enabled == false
            ? "إعادة التفعيل عند بدء التشغيل"
            : "تعطيل من بدء التشغيل";
        AutorunToggleItem.IsEnabled = row is not null;
    }

    private void OnAutorunOpenLocation(object sender, RoutedEventArgs e)
    {
        var path = SelectedAutorun?.Entry.ImagePath ?? SelectedAutorun?.Entry.ItemPath;
        if (string.IsNullOrEmpty(path)) return;

        try
        {
            // Select the file in Explorer when it exists; otherwise just open the folder.
            if (System.IO.File.Exists(path))
                System.Diagnostics.Process.Start("explorer.exe", $"/select,\"{path}\"");
            else if (System.IO.Directory.Exists(System.IO.Path.GetDirectoryName(path)))
                System.Diagnostics.Process.Start("explorer.exe", $"\"{System.IO.Path.GetDirectoryName(path)}\"");
            else
                MessageBox.Show("الملف والمجلد غير موجودين — المدخل يشير إلى مسار محذوف.",
                    "Meow Security", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch { }
    }

    private void OnAutorunToggle(object sender, RoutedEventArgs e)
    {
        var row = SelectedAutorun;
        if (row is null) return;

        bool enable = !row.Entry.Enabled;
        var result = Sentinel.Core.Persistence.AutorunControl.SetEnabled(row.Entry, enable);
        ReportAutorunResult(result, row.Entry.Name);
        if (result.Ok) ScanAutoruns();
    }

    private void OnAutorunRemove(object sender, RoutedEventArgs e)
    {
        var row = SelectedAutorun;
        if (row is null) return;

        if (row.Entry.Kind is Sentinel.Core.Persistence.AutorunKind.Service
                           or Sentinel.Core.Persistence.AutorunKind.ScheduledTask)
        {
            MessageBox.Show("الخدمات والمهام المجدولة تعطل ولا تحذف — التعطيل قابل للتراجع والحذف لا.",
                "Meow Security", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var confirm = MessageBox.Show(
            $"حذف \"{row.Entry.Name}\" نهائيا من بدء التشغيل؟\n\n{row.Entry.Command}\n\n" +
            "الملف نفسه لا يحذف — يحذف المدخل الذي يشغله فقط.",
            "تأكيد الحذف", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes) return;

        var result = Sentinel.Core.Persistence.AutorunControl.Remove(row.Entry);
        ReportAutorunResult(result, row.Entry.Name);
        if (result.Ok) ScanAutoruns();
    }

    private void ReportAutorunResult(Sentinel.Core.Persistence.ControlResult result, string name)
    {
        if (result.Ok)
        {
            AutorunSummary.Text = $"{name}: {result.Message}";
            return;
        }

        if (result.NeedsElevation &&
            MessageBox.Show($"{result.Message}\n\nتشغيل البرنامج بصلاحية المدير الآن؟",
                "Meow Security", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
        {
            OnElevate(this, new RoutedEventArgs());
            return;
        }

        if (!result.NeedsElevation)
            MessageBox.Show(result.Message, "Meow Security", MessageBoxButton.OK, MessageBoxImage.Warning);
    }

    private void OnAutorunFilter(object sender, RoutedEventArgs e)
    {
        if (_autorunsView is null) return;
        _autorunsView.Refresh();
        UpdateAutorunSummary(_autoruns.Count(r => r.IsFlagged));
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

            LiveRow row;
            if (_byPid.TryGetValue(p.Pid, out var existing))
            {
                existing.Update(p);
                existing.TickHighlight();
                row = existing;
            }
            else
            {
                row = new LiveRow(p);
                row.MarkNew();
                _byPid[p.Pid] = row;
                _rows.Add(row);
                if (row.IsFlagged) AlertVerdict(row);
            }

            if (!row.HasReputation) _reputation.Enqueue(row);
        }

        for (int i = _rows.Count - 1; i >= 0; i--)
        {
            if (!seen.Contains(_rows[i].Pid))
            {
                _byPid.Remove(_rows[i].Pid);
                _rows.RemoveAt(i);
            }
        }

        // Behavioural pass: cheap, local, and the only thing that catches a signed LOLBin
        // being driven by something it has no business being driven by.
        RecordEvents(_watcher.Inspect(sample));

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
        int score = Math.Clamp(100 - alarm * 22 - review * 5, 0, 100);
        if (alarm > 0)
        {
            color = Res("Red");
            HeroTitle.Text = $"انتبه — {alarm} عنصر يحتاج تدقيقا";
            HeroSub.Text = "افتح صفحة التهديدات لمراجعة العناصر الحمراء";
        }
        else if (review > 0)
        {
            color = Res("Amber");
            HeroTitle.Text = "جهازك سليم، مع عناصر للمراجعة";
            HeroSub.Text = $"{review} عنصر بلا توقيع خارج مجلدات النظام — غالبا عادي";
        }
        else
        {
            color = Res("Green");
            HeroTitle.Text = "جهازك سليم";
            HeroSub.Text = "كل العمليات موقعة، ولا كود محقون، ولا عملية مخفية";
        }
        HeroTitle.Foreground = color;
        HeroScore.Text = score.ToString();
        HeroScore.Foreground = color;
        Shield.Accent = color;
        Shield.Score = score;
        LiveDot.Fill = color;
    }

    // ---------------- toolbar ----------------

    private void OnPauseToggle(object sender, RoutedEventArgs e)
    {
        _paused = !_paused;
        PauseButton.Content = _paused ? "استئناف" : "إيقاف مؤقت";
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
            MessageBox.Show(this, "تعذر الإيقاف — قد تكون عملية محمية.", "تنبيه",
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
            MessageBox.Show(this, $"تعذر الإنهاء: {ex.Message}", "خطأ",
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

    // ---------------- instant alerts ----------------

    private void OnFlaggedByReputation(LiveRow row, ThreatLevel level)
    {
        if (!_settings.Notifications) return;
        if (!_alerted.Add(row.Pid)) return;

        var (title, accent) = level == ThreatLevel.Malicious
            ? ($"عملية خبيثة: {row.Name}", Res("Red"))
            : ($"عملية مشبوهة: {row.Name}", Res("Amber"));
        ShowAlert(title, "طابقت قاعدة تهديدات عالمية. افتح صفحة التهديدات للمراجعة.", accent);
    }

    private void AlertVerdict(LiveRow row)
    {
        if (!_settings.Notifications) return;
        if (row.Verdict != Verdict.Suspicious) return; // only the serious ones pop up
        if (!_alerted.Add(row.Pid)) return;

        var reason = string.IsNullOrEmpty(row.Reasons) ? "ظهرت عملية مشبوهة." : row.Reasons;
        ShowAlert($"عملية مشبوهة: {row.Name}", reason, Res("Red"));
    }

    private void ShowAlert(string title, string detail, Brush accent) =>
        ShowAlert(title, detail, accent, serious: true);

    /// <summary>
    /// Raises an alert everywhere it should be heard.
    ///
    /// An in-app banner only works if the app is the thing being looked at, which for a
    /// background monitor is the exception. So a serious finding also goes to the notification
    /// area and, unless muted, makes a sound — the point of a monitor is to interrupt.
    /// </summary>
    private void ShowAlert(string title, string detail, Brush accent, bool serious)
    {
        if (_settings.SystemNotifications)
        {
            EnsureTray();
            _tray?.Notify(title, detail, serious);
        }

        if (_settings.AlertSound)
        {
            try
            {
                if (serious) System.Media.SystemSounds.Hand.Play();
                else System.Media.SystemSounds.Exclamation.Play();
            }
            catch { /* no audio device */ }
        }

        // The window may be hidden in the tray, in which case the banner has no audience.
        if (!IsVisible) return;

        ToastTitle.Text = title;
        ToastDetail.Text = detail;
        ToastBar.Background = accent;
        Toast.Visibility = Visibility.Visible;

        var fade = new System.Windows.Media.Animation.DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(220));
        var slide = new System.Windows.Media.Animation.DoubleAnimation(-30, 0, TimeSpan.FromMilliseconds(260))
        { EasingFunction = new System.Windows.Media.Animation.CubicEase() };
        Toast.BeginAnimation(OpacityProperty, fade);
        ToastShift.BeginAnimation(TranslateTransform.XProperty, slide);

        _toastTimer.Stop();
        _toastTimer.Start();
    }

    private void HideToast()
    {
        _toastTimer.Stop();
        var fade = new System.Windows.Media.Animation.DoubleAnimation(Toast.Opacity, 0, TimeSpan.FromMilliseconds(220));
        fade.Completed += (_, _) => Toast.Visibility = Visibility.Collapsed;
        Toast.BeginAnimation(OpacityProperty, fade);
    }

    private void OnToastDismiss(object sender, RoutedEventArgs e) => HideToast();

    private void OnToastReview(object sender, RoutedEventArgs e)
    {
        NavAlerts.IsChecked = true;
        HideToast();
    }

    /// <summary>
    /// Opens a credit link in the user's browser. UseShellExecute is required — without it
    /// .NET tries to execute the URL as a file — and only the http(s) links this page carries
    /// are ever passed through, so a Tag can never become a command.
    /// </summary>
    private void OnOpenLink(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (sender is not FrameworkElement { Tag: string url }) return;
        if (!url.StartsWith("https://", StringComparison.Ordinal)) return;

        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(url)
            {
                UseShellExecute = true,
            });
        }
        catch { /* no browser registered */ }
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
