using System.Windows;
using Sentinel.Core.Intel;

namespace Sentinel.Gui;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        // Apply the saved theme to the palette before the first window binds to it.
        ThemeManager.Apply(IntelSettings.Load().Theme);
        new MainWindow().Show();
    }
}
