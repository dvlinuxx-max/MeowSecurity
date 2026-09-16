using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Threading;
using Sentinel.Core.Intel;

namespace Sentinel.Gui;

/// <summary>
/// Catches what would otherwise be a silent disappearance.
///
/// A security monitor that vanishes is worse than one that never started: the user believes
/// they are being watched and they are not. Worse, an elevated crash files its report under
/// ProgramData where the user cannot read it, so "it just closes" is all anyone ever learns.
/// This writes the exception where the user can actually find it and says so out loud.
/// </summary>
public static class CrashLog
{
    public static string FilePath => Path.Combine(IntelSettings.ConfigDirectory, "crash.log");

    public static void Install(Application app)
    {
        app.DispatcherUnhandledException += (_, e) =>
        {
            Write("UI thread", e.Exception);
            Tell(e.Exception);
            e.Handled = true;   // stay alive: a monitor that survives the bug keeps monitoring
        };

        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
            Write("background thread", e.ExceptionObject as Exception);

        System.Threading.Tasks.TaskScheduler.UnobservedTaskException += (_, e) =>
        {
            Write("task", e.Exception);
            e.SetObserved();
        };
    }

    public static void Write(string where, Exception? ex)
    {
        if (ex is null) return;
        try
        {
            var sb = new StringBuilder();
            sb.AppendLine(new string('=', 72));
            sb.AppendLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss}  ({where})");
            sb.AppendLine($"elevated: {IsElevated()}   process: {Environment.ProcessPath}");
            sb.AppendLine($"os: {Environment.OSVersion.VersionString}   clr: {Environment.Version}");
            for (var e = ex; e is not null; e = e.InnerException)
            {
                sb.AppendLine($"--- {e.GetType().FullName}: {e.Message}");
                sb.AppendLine(e.StackTrace);
            }
            Directory.CreateDirectory(IntelSettings.ConfigDirectory);
            File.AppendAllText(FilePath, sb.ToString(), new UTF8Encoding(false));
        }
        catch { /* the logger must never be the thing that kills the app */ }
    }

    private static void Tell(Exception ex)
    {
        try
        {
            MessageBox.Show(
                $"حدث خطأ غير متوقع، والمراقبة مستمرة.\n\n{ex.GetType().Name}: {ex.Message}\n\nالتفاصيل في:\n{FilePath}",
                "Sentinel", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        catch { }
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
}
