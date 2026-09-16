using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;

namespace MeowSecurity.Gui;

/// <summary>
/// The notification-area icon, spoken directly to the shell.
///
/// WPF ships no tray icon, and the usual answer — dragging in all of WinForms for one
/// NOTIFYICONDATA — costs more than the feature. This talks to Shell_NotifyIcon itself, in
/// the same spirit as the rest of the engine's native interop, through a message-only window
/// that exists purely to receive the icon's callbacks.
///
/// Without this the "keep monitoring in the background" setting is a lie: the user ticks it,
/// closes the window, and nothing watches anything.
/// </summary>
public sealed class TrayIcon : IDisposable
{
    private const int WM_APP = 0x8000;
    private const int CallbackMessage = WM_APP + 1;

    private const int WM_LBUTTONUP = 0x0202;
    private const int WM_LBUTTONDBLCLK = 0x0203;
    private const int WM_RBUTTONUP = 0x0205;
    private const int NIN_BALLOONUSERCLICK = WM_APP + 5;

    private const int NIM_ADD = 0, NIM_MODIFY = 1, NIM_DELETE = 2;
    private const int NIF_MESSAGE = 0x01, NIF_ICON = 0x02, NIF_TIP = 0x04, NIF_INFO = 0x10;
    private const int NIIF_INFO = 0x01, NIIF_WARNING = 0x02, NIIF_ERROR = 0x03;

    private readonly HwndSource _sink;
    private readonly uint _taskbarCreated;
    private IntPtr _icon;
    private bool _added;
    private string _tip;

    /// <summary>Left-click or double-click on the icon, or a click on a balloon.</summary>
    public event Action? Activated;

    /// <summary>Right-click: the caller shows its own menu.</summary>
    public event Action? ContextMenuRequested;

    public TrayIcon(string tip)
    {
        _tip = tip;

        // A message-only window: never visible, never in the taskbar, exists only as the
        // address the shell sends icon events to.
        _sink = new HwndSource(new HwndSourceParameters("MeowSecurityTraySink")
        {
            ParentWindow = new IntPtr(-3),   // HWND_MESSAGE
            Width = 0,
            Height = 0,
        });
        _sink.AddHook(OnMessage);

        // The shell broadcasts this when Explorer restarts; the icon must be re-added or it
        // silently disappears for the rest of the session.
        _taskbarCreated = RegisterWindowMessage("TaskbarCreated");

        _icon = LoadAppIcon();
        Add();
    }

    /// <summary>
    /// Whether the shell actually accepted the icon. The caller must check this before it
    /// hides its window: an icon that never appeared leaves the user with a running process
    /// and no way back to it.
    /// </summary>
    public bool IsVisible => _added;

    public void Show() => Add();

    public void UpdateTip(string tip)
    {
        _tip = tip;
        if (_added) Send(NIM_MODIFY, NIF_TIP);
    }

    /// <summary>A balloon in the notification area — how an alert reaches a hidden window.</summary>
    public void Notify(string title, string message, bool serious)
    {
        if (!_added) Add();
        var data = Build(NIF_INFO);
        data.szInfoTitle = Trim(title, 63);
        data.szInfo = Trim(message, 255);
        data.dwInfoFlags = serious ? NIIF_WARNING : NIIF_INFO;
        Shell_NotifyIcon(NIM_MODIFY, ref data);
    }

    private void Add()
    {
        if (_added) return;
        var data = Build(NIF_MESSAGE | NIF_ICON | NIF_TIP);
        _added = Shell_NotifyIcon(NIM_ADD, ref data);
    }

    private void Send(int message, int flags)
    {
        var data = Build(flags);
        Shell_NotifyIcon(message, ref data);
    }

    private NOTIFYICONDATA Build(int flags) => new()
    {
        cbSize = Marshal.SizeOf<NOTIFYICONDATA>(),
        hWnd = _sink.Handle,
        uID = 1,
        uFlags = flags,
        uCallbackMessage = CallbackMessage,
        hIcon = _icon,
        szTip = Trim(_tip, 127),
        szInfo = "",
        szInfoTitle = "",
    };

    private static string Trim(string s, int max) => s.Length <= max ? s : s[..max];

    private IntPtr OnMessage(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (msg == _taskbarCreated)
        {
            _added = false;
            Add();
            handled = true;
        }
        else if (msg == CallbackMessage)
        {
            switch ((int)lParam)
            {
                case WM_LBUTTONUP:
                case WM_LBUTTONDBLCLK:
                case NIN_BALLOONUSERCLICK:
                    Activated?.Invoke();
                    break;
                case WM_RBUTTONUP:
                    ContextMenuRequested?.Invoke();
                    break;
            }
            handled = true;
        }
        return IntPtr.Zero;
    }

    /// <summary>
    /// The icon comes out of our own executable, so the tray, the taskbar and Explorer all
    /// show the same thing. Falls back to the system icon if the exe carries none.
    /// </summary>
    private static IntPtr LoadAppIcon()
    {
        try
        {
            var exe = Environment.ProcessPath;
            if (!string.IsNullOrEmpty(exe) &&
                ExtractIconEx(exe, 0, out _, out var small, 1) > 0 && small != IntPtr.Zero)
                return small;
        }
        catch { /* fall through to the system icon */ }
        return LoadIcon(IntPtr.Zero, new IntPtr(32512)); // IDI_APPLICATION
    }

    /// <summary>
    /// A tray context menu only behaves — dismissing on click-away — when its owner is the
    /// foreground window. The shell's own documented workaround, still required.
    /// </summary>
    public void PrepareForMenu()
    {
        SetForegroundWindow(_sink.Handle);
    }

    public void Dispose()
    {
        if (_added)
        {
            var data = Build(0);
            Shell_NotifyIcon(NIM_DELETE, ref data);
            _added = false;
        }
        if (_icon != IntPtr.Zero) { DestroyIcon(_icon); _icon = IntPtr.Zero; }
        _sink.RemoveHook(OnMessage);
        _sink.Dispose();
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NOTIFYICONDATA
    {
        public int cbSize;
        public IntPtr hWnd;
        public int uID;
        public int uFlags;
        public int uCallbackMessage;
        public IntPtr hIcon;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string szTip;
        public int dwState;
        public int dwStateMask;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string szInfo;
        public int uVersion;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string szInfoTitle;
        public int dwInfoFlags;
        public Guid guidItem;
        public IntPtr hBalloonIcon;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern bool Shell_NotifyIcon(int message, ref NOTIFYICONDATA data);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern int ExtractIconEx(string file, int index, out IntPtr large, out IntPtr small, int count);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern uint RegisterWindowMessage(string message);

    [DllImport("user32.dll")]
    private static extern IntPtr LoadIcon(IntPtr instance, IntPtr name);

    [DllImport("user32.dll")]
    private static extern bool DestroyIcon(IntPtr icon);

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hwnd);
}
