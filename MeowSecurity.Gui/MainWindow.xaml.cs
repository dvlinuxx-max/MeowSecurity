using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Threading;
using MeowSecurity.Core.Detect;
using MeowSecurity.Core.Intel;
using MeowSecurity.Core.Ipc;
using MeowSecurity.Core.Live;
using MeowSecurity.Core.Localization;
using MeowSecurity.Core.Processes;

namespace MeowSecurity.Gui;

public partial class MainWindow : Window
{
    private readonly ObservableCollection<LiveRow> _rows = [];
    private readonly Dictionary<int, LiveRow> _byPid = [];
    private readonly LiveSampler _sampler = new();
    private readonly LiveEnricher _enricher = new();
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(1) };

    private readonly IntelSettings _settings = IntelSettings.Load();
    private bool _loadingSettings;

    private readonly HashSet<int> _alerted = [];
    private readonly DispatcherTimer _toastTimer = new() { Interval = TimeSpan.FromSeconds(9) };

    private TrayIcon? _tray;
    private bool _exiting;
    private bool _toldUserAboutTray;

    private readonly EventStore _events = new();
    private readonly BehaviorWatcher _watcher;
    private readonly MeowSecurity.Core.Etw.ProcessStartWatcher _etw = new();
    private readonly MeowSecurity.Core.Health.HealthMonitor _health = new();
    private readonly ObservableCollection<EventRow> _eventRows = [];
    private ListCollectionView _eventsView = null!;

    private ListCollectionView _threatsView = null!;
    private ListCollectionView _netView = null!;

    private DateTime _lastNetRead = DateTime.UtcNow;
    private double _netMax = 64 * 1024;
    private bool _paused;

    public MainWindow()
    {
        _watcher = new BehaviorWatcher(_events);

        InitializeComponent();

        // Arabic reads right to left, English left to right. Every alignment in the window
        // was written to follow the flow direction, so this one line mirrors the whole layout.
        FlowDirection = Strings.IsRightToLeft ? FlowDirection.RightToLeft : FlowDirection.LeftToRight;

        Grid.ItemsSource = _rows;
        LoadEventHistory();
        _threatsView = new ListCollectionView(_rows) { Filter = o => o is LiveRow r && r.IsFlagged };
        // A process moving bytes belongs on this page even if its connection is already gone.
        _netView = new ListCollectionView(_rows)
        { Filter = o => o is LiveRow r && (r.RemoteConns > 0 || r.NetTotal > 0) };
        ThreatGrid.ItemsSource = _threatsView;
        AttentionList.ItemsSource = _threatsView;
        NetGrid.ItemsSource = _netView;

        NetSpark.Stroke = Res("NetIn"); NetSpark.Fill = Res("NetFill");
        NetBigGraph.Stroke = Res("NetIn"); NetBigGraph.Fill = Res("NetFill");

        _toastTimer.Tick += (_, _) => HideToast();
        LoadSettingsUi();

        // Read the version off the assembly so the about card can never drift from the build.
        var v = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
        AboutVersion.Text = Strings.T("about.version", v?.Major ?? 0, v?.Minor ?? 1);

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
    }

    // ---------------- settings ----------------

    private void LoadSettingsUi()
    {
        _loadingSettings = true;
        ChkLight.IsChecked = string.Equals(_settings.Theme, "light", StringComparison.OrdinalIgnoreCase);
        ChkEnglish.IsChecked = !Strings.IsRightToLeft;
        ChkNotify.IsChecked = _settings.Notifications;
        ChkSystemNotify.IsChecked = _settings.SystemNotifications;
        ChkSound.IsChecked = _settings.AlertSound;
        ChkBackground.IsChecked = _settings.RunInBackground;
        ChkHealth.IsChecked = _settings.HealthMonitoring;
        RefreshStartupSwitch();
        _loadingSettings = false;

        if (IsElevated())
        {
            ElevateStatus.Text = Strings.T("elev.full");
            ElevateBtn.Visibility = Visibility.Collapsed;
        }
        else
        {
            ElevateStatus.Text = Strings.T("elev.limited");
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

    /// <summary>
    /// Starting with Windows is a scheduled task, not a Run key, because the live capture
    /// needs administrator rights — a Run entry would bring the monitor back after every
    /// reboot quietly missing the events it exists to catch.
    ///
    /// The switch reflects whether the task actually exists rather than a saved preference,
    /// so it can never claim something the machine disagrees with.
    /// </summary>
    private void OnStartupToggle(object sender, RoutedEventArgs e)
    {
        if (_loadingSettings) return;

        bool wanted = ChkStartup.IsChecked == true;
        var exe = Environment.ProcessPath;
        if (exe is null) return;

        var result = wanted
            ? MeowSecurity.Core.Persistence.StartupRegistration.Register(exe)
            : MeowSecurity.Core.Persistence.StartupRegistration.Unregister();

        if (result.Ok)
        {
            StartupStatus.Text = result.Message;
            return;
        }

        // Put the switch back where reality left it before explaining why.
        _loadingSettings = true;
        ChkStartup.IsChecked = !wanted;
        _loadingSettings = false;

        if (result.NeedsElevation &&
            MessageBox.Show(Strings.T("msg.elevate-now", result.Message),
                "Meow Security", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
        {
            OnElevate(this, new RoutedEventArgs());
            return;
        }

        StartupStatus.Text = result.Message;
    }

    private void RefreshStartupSwitch()
    {
        bool registered = MeowSecurity.Core.Persistence.StartupRegistration.IsRegistered();
        ChkStartup.IsChecked = registered;
        StartupStatus.Text = registered
            ? Strings.T("startup.on")
            : Strings.T("startup.off");
    }

    /// <summary>
    /// Switching language rebuilds the window, for the same reason switching theme does:
    /// XAML resolves its strings once, when it is loaded.
    /// </summary>
    private void OnLanguageToggle(object sender, RoutedEventArgs e)
    {
        if (_loadingSettings) return;

        _settings.Language = ChkEnglish.IsChecked == true ? "en" : "ar";
        _settings.Save();
        Strings.Language = Strings.Parse(_settings.Language);

        var fresh = new MainWindow();
        fresh.Show();
        fresh.NavSettings.IsChecked = true;
        _exiting = true;
        _timer.Stop();
        Close();
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


    private static string? Nz(string s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();







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
            _tray?.Notify(Strings.T("tray.still.title"),
                Strings.T("tray.still.body"), serious: false);
        }
    }

    private void EnsureTray()
    {
        if (_tray is not null) return;

        _tray = new TrayIcon(Strings.T("tray.tip.on"));
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
        menu.Items.Add(Item(Strings.T("tray.open"), RestoreFromTray));
        menu.Items.Add(Item(_paused ? Strings.T("tray.resume") : Strings.T("tray.pause"), () =>
        {
            OnPauseToggle(this, new RoutedEventArgs());
            _tray?.UpdateTip(_paused ? Strings.T("tray.tip.off") : Strings.T("tray.tip.on"));
        }));
        menu.Items.Add(new Separator());
        menu.Items.Add(Item(Strings.T("tray.exit"), ExitApp));
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
    private readonly EngineClient _engine = new();

    /// <summary>
    /// Starts the live capture by whichever route is available.
    ///
    /// Elevated, the trace session opens in this process and there is nothing to negotiate.
    /// Otherwise the small elevated helper does it and streams the events back, which is the
    /// only shape a packaged application is allowed to take: the interface stays unprivileged
    /// and one prompt covers one job.
    /// </summary>
    private async void StartLiveCapture()
    {
        _etw.Started += OnProcessStarted;

        if (IsElevated())
        {
            _etw.Start();
            UpdateCaptureStatus();
            return;
        }

        UpdateCaptureStatus();   // shows the "needs administrator" state while we ask
        _engine.ProcessStarted += OnProcessStarted;

        if (!await _engine.ConnectAsync())
        {
            CaptureStatus.Text = _engine.Declined
                ? Strings.T("etw.declined")
                : Strings.T("etw.unavailable", _engine.Error ?? "");
            return;
        }

        var reply = await _engine.SendAsync(new Request { Command = Command.StartCapture });
        CaptureStatus.Text = reply?.Ok == true
            ? Strings.T("etw.on.helper")
            : Strings.T("etw.unavailable", reply?.Text ?? _engine.Error ?? "");
        CaptureStatus.Foreground = Res(reply?.Ok == true ? "Green" : "Muted");
    }

    private void UpdateCaptureStatus()
    {
        if (CaptureStatus is null) return;
        CaptureStatus.Text = _etw.State switch
        {
            MeowSecurity.Core.Etw.EtwState.Running => Strings.T("etw.on"),
            MeowSecurity.Core.Etw.EtwState.NeedsElevation =>
                Strings.T("etw.off"),
            _ => Strings.T("etw.unavailable", _etw.Error),
        };
        CaptureStatus.Foreground = Res(_etw.State == MeowSecurity.Core.Etw.EtwState.Running ? "Green" : "Muted");
    }

    /// <summary>Arrives on an ETW thread, so everything touching the UI hops to the dispatcher.</summary>
    private void OnProcessStarted(MeowSecurity.Core.Etw.ProcessStart p)
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
            ? Strings.T("summary.no-alerts")
            : Strings.T("summary.alerts", _alerts.Count, serious);
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
                MessageBox.Show(Strings.T("msg.file-gone"), "Meow Security",
                    MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch { }
    }

    private void OnAlertKill(object sender, RoutedEventArgs e)
    {
        var card = CardFrom(sender);
        if (card is null) return;

        if (MessageBox.Show(Strings.T("confirm.kill.body", card.Event.Process, card.Event.Pid) +
                            Strings.T("msg.kill-warning"),
                Strings.T("common.confirm"), MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;

        try
        {
            using var p = System.Diagnostics.Process.GetProcessById(card.Event.Pid);
            p.Kill();
            AlertSummary.Text = Strings.T("msg.killed", card.Event.Process);
        }
        catch (ArgumentException)
        {
            MessageBox.Show(Strings.T("msg.already-gone"), "Meow Security",
                MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(Strings.T("msg.kill-failed", ex.Message),
                "Meow Security", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
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
            ? Strings.T("summary.no-events")
            : Strings.T("summary.events", _eventRows.Count, serious);
        EventHint.Visibility = _eventRows.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        EventBadge.Visibility = serious > 0 ? Visibility.Visible : Visibility.Collapsed;
        EventBadgeText.Text = serious > 99 ? "99+" : serious.ToString();
    }

    private void OnEventFilter(object sender, RoutedEventArgs e) => _eventsView?.Refresh();

    private void OnClearEvents(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show(Strings.T("confirm.clear-log"), Strings.T("btn.clear-log"),
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
        AutorunSummary.Text = Strings.T("status.scanning");
        AutorunHint.Visibility = Visibility.Collapsed;

        var scanner = new MeowSecurity.Core.Persistence.AutorunScanner();
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
        AutorunScanBtn.Content = Strings.T("btn.rescan");
        _autorunsScanning = false;
    }

    private void UpdateAutorunSummary(int flagged)
    {
        int hidden = AutorunShowSystem.IsChecked == true ? 0 : _autoruns.Count(r => r.IsSystem);
        var parts = new List<string> { Strings.T("summary.autoruns", _autoruns.Count - hidden) };
        parts.Add(flagged > 0 ? Strings.T("summary.flagged", flagged) : Strings.T("summary.all-clear"));
        if (hidden > 0) parts.Add(Strings.T("summary.hidden", hidden));
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
            row!.Entry.Kind is MeowSecurity.Core.Persistence.AutorunKind.RunKey
                            or MeowSecurity.Core.Persistence.AutorunKind.StartupFolder;
        AutorunToggleBtn.Content = row?.Entry.Enabled == false ? Strings.T("btn.enable") : Strings.T("btn.disable");
    }

    private void OnAutorunMenuOpened(object sender, RoutedEventArgs e)
    {
        var row = SelectedAutorun;
        AutorunToggleItem.Header = row?.Entry.Enabled == false
            ? Strings.T("menu.enable-startup")
            : Strings.T("menu.disable-startup");
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
                MessageBox.Show(Strings.T("msg.path-gone"),
                    "Meow Security", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch { }
    }

    private void OnAutorunToggle(object sender, RoutedEventArgs e)
    {
        var row = SelectedAutorun;
        if (row is null) return;

        bool enable = !row.Entry.Enabled;
        var result = MeowSecurity.Core.Persistence.AutorunControl.SetEnabled(row.Entry, enable);
        ReportAutorunResult(result, row.Entry.Name);
        if (result.Ok) ScanAutoruns();
    }

    private void OnAutorunRemove(object sender, RoutedEventArgs e)
    {
        var row = SelectedAutorun;
        if (row is null) return;

        if (row.Entry.Kind is MeowSecurity.Core.Persistence.AutorunKind.Service
                           or MeowSecurity.Core.Persistence.AutorunKind.ScheduledTask)
        {
            MessageBox.Show(Strings.T("msg.no-delete"),
                "Meow Security", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var confirm = MessageBox.Show(
            Strings.T("confirm.remove.entry", row.Entry.Name, row.Entry.Command) +
            Strings.T("msg.entry-only"),
            Strings.T("confirm.delete.title"), MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes) return;

        var result = MeowSecurity.Core.Persistence.AutorunControl.Remove(row.Entry);
        ReportAutorunResult(result, row.Entry.Name);
        if (result.Ok) ScanAutoruns();
    }

    private void ReportAutorunResult(MeowSecurity.Core.Persistence.ControlResult result, string name)
    {
        if (result.Ok)
        {
            AutorunSummary.Text = $"{name}: {result.Message}";
            return;
        }

        if (result.NeedsElevation &&
            MessageBox.Show(Strings.T("msg.elevate-now", result.Message),
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

        // Per-process throughput, if the live capture is running. Windows keeps no such
        // counter, so these are the kernel's own packets added up since the last tick.
        if (_etw.State == MeowSecurity.Core.Etw.EtwState.Running)
        {
            var byPid = _etw.TakeNetworkTotals();
            double seconds = Math.Max(0.25, (DateTime.UtcNow - _lastNetRead).TotalSeconds);
            _lastNetRead = DateTime.UtcNow;

            foreach (var p in sample)
            {
                if (!byPid.TryGetValue(p.Pid, out var bytes)) continue;
                p.NetInBytesPerSec = (long)(bytes.In / seconds);
                p.NetOutBytesPerSec = (long)(bytes.Out / seconds);
            }
        }

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
        RecordEvents(_watcher.InspectMachine());

        // Device health: the symptom people actually notice, and how a miner announces itself.
        if (_settings.HealthMonitoring)
        {
            string? heaviest = sample
                .Where(p => p.Pid > 4)
                .OrderByDescending(p => p.CpuPercent)
                .FirstOrDefault()?.Name;

            if (_health.Observe(pulse, heaviest, DateTime.Now) is { } strain)
            {
                _events.Append(strain);
                RecordEvents([strain]);
            }
        }

        UpdateReadouts(pulse);
        UpdateVerdict(suspicious, review, hidden);

        _threatsView.Refresh();
        _netView.Refresh();
        if (!string.IsNullOrEmpty(Search.Text))
            CollectionViewSource.GetDefaultView(_rows)?.Refresh();

        _enricher.EnrichMissing(sample, scanMemory: true);
        _enricher.DeepScanIfDue(sample);
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
        ThreadSub.Text = Strings.T("unit.threads", pulse.ThreadCount);
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
            HeroTitle.Text = Strings.T("hero.alarm", alarm);
            HeroSub.Text = Strings.T("hero.review");
        }
        else if (review > 0)
        {
            color = Res("Amber");
            HeroTitle.Text = Strings.T("hero.clean-review");
            HeroSub.Text = Strings.T("hero.review-count", review);
        }
        else
        {
            color = Res("Green");
            HeroTitle.Text = Strings.T("hero.clean");
            HeroSub.Text = Strings.T("hero.clean.sub");
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
        PauseButton.Content = _paused ? Strings.T("btn.resume") : Strings.T("btn.pause");
        LiveLabel.Text = _paused ? Strings.T("status.paused") : Strings.T("status.monitoring");
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
        if (RowFrom(sender) is { } r && !MeowSecurity.Core.Native.ProcessControl.Suspend(r.Pid))
            MessageBox.Show(this, Strings.T("msg.suspend-failed"), Strings.T("common.alert"),
                MessageBoxButton.OK, MessageBoxImage.Warning);
    }

    private void OnResumeProcess(object sender, RoutedEventArgs e)
    {
        if (RowFrom(sender) is { } r) MeowSecurity.Core.Native.ProcessControl.Resume(r.Pid);
    }

    private void OnKillProcess(object sender, RoutedEventArgs e)
    {
        if (RowFrom(sender) is not { } r) return;
        var ask = MessageBox.Show(this,
            Strings.T("confirm.kill.system", r.Name, r.Pid),
            Strings.T("confirm.kill.title"), MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (ask != MessageBoxResult.Yes) return;
        try
        {
            using var p = System.Diagnostics.Process.GetProcessById(r.Pid);
            p.Kill();
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, Strings.T("msg.kill-error", ex.Message), Strings.T("common.error"),
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


    private void AlertVerdict(LiveRow row)
    {
        if (!_settings.Notifications) return;
        if (row.Verdict != Verdict.Suspicious) return; // only the serious ones pop up
        if (!_alerted.Add(row.Pid)) return;

        var reason = string.IsNullOrEmpty(row.Reasons) ? Strings.T("alert.suspicious.body") : row.Reasons;
        ShowAlert(Strings.T("alert.suspicious", row.Name), reason, Res("Red"));
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
        string[] u = { Strings.T("unit.bytes"), Strings.T("unit.kilo"), Strings.T("unit.mega"), Strings.T("unit.giga"), Strings.T("unit.tera") };
        double v = b; int i = 0;
        while (v >= 1024 && i < u.Length - 1) { v /= 1024; i++; }
        return $"{v:0.#} {u[i]}";
    }

    private static string Rate(long bps)
    {
        if (bps <= 0) return "0";
        string[] u = { Strings.T("unit.rate.b"), Strings.T("unit.rate.k"), Strings.T("unit.rate.m"), Strings.T("unit.rate.g") };
        double v = bps; int i = 0;
        while (v >= 1024 && i < u.Length - 1) { v /= 1024; i++; }
        return $"{v:0.#} {u[i]}";
    }
}
