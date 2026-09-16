using System.Windows;
using Sentinel.Core.Intel;

namespace Sentinel.Gui;

public partial class App : Application
{
    // Held for the lifetime of the process; releasing it is what lets the next launch win.
    private static System.Threading.Mutex? _instanceLock;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        CrashLog.Install(this);

        if (!ClaimSingleInstance())
        {
            // A second monitor would duplicate every alert and write the same event twice.
            // Surface the copy that is already running instead of quietly adding another.
            FocusRunningInstance();
            Shutdown();
            return;
        }

        try
        {
            // Apply the saved theme to the palette before the first window binds to it.
            ThemeManager.Apply(IntelSettings.Load().Theme);
            new MainWindow().Show();
        }
        catch (Exception ex)
        {
            // A failure in here means no window ever appears, which from the outside looks
            // exactly like the app "not starting" — the least debuggable failure there is.
            CrashLog.Write("startup", ex);
            MessageBox.Show(
                $"تعذر بدء Meow Security.\n\n{ex.GetType().Name}: {ex.Message}\n\nالتفاصيل في:\n{CrashLog.FilePath}",
                "Meow Security", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(1);
        }
    }

    /// <summary>
    /// True if this process is the one monitor. The mutex is per-session and named, so an
    /// elevated copy and an ordinary one see each other — which matters, because running both
    /// is exactly the confusion this prevents.
    /// </summary>
    private static bool ClaimSingleInstance()
    {
        try
        {
            _instanceLock = new System.Threading.Mutex(initiallyOwned: true,
                @"Local\MeowSecurity.Monitor.SingleInstance", out bool created);
            return created;
        }
        catch (UnauthorizedAccessException)
        {
            // The mutex exists but belongs to a copy at a different integrity level.
            return false;
        }
        catch
        {
            return true;   // never let this check be the reason the app will not start
        }
    }

    private static void FocusRunningInstance()
    {
        try
        {
            int me = Environment.ProcessId;
            foreach (var p in System.Diagnostics.Process.GetProcessesByName(System.Diagnostics.Process.GetCurrentProcess().ProcessName))
            {
                using (p)
                {
                    if (p.Id == me || p.MainWindowHandle == IntPtr.Zero) continue;
                    ShowWindow(p.MainWindowHandle, 9);   // SW_RESTORE
                    SetForegroundWindow(p.MainWindowHandle);
                    return;
                }
            }
        }
        catch { /* the other copy may be elevated and out of reach — nothing to do */ }
    }

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hwnd);

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr hwnd, int cmd);
}
