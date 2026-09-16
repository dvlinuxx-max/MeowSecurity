using System.Windows;
using Sentinel.Core.Intel;

namespace Sentinel.Gui;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        CrashLog.Install(this);

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
                $"تعذر بدء Sentinel.\n\n{ex.GetType().Name}: {ex.Message}\n\nالتفاصيل في:\n{CrashLog.FilePath}",
                "Sentinel", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(1);
        }
    }
}
