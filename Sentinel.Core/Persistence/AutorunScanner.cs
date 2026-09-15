using Microsoft.Win32;
using Sentinel.Core.Processes;

namespace Sentinel.Core.Persistence;

/// <summary>
/// Enumerates the common auto-start locations — registry Run/RunOnce keys (per-user and
/// machine, including the 32-bit view) and the Startup folders — resolves each to its target
/// executable, and signature-checks it. Unsigned or temp-folder autoruns are exactly the
/// persistence footholds malware leaves behind, so they are surfaced, not hidden.
/// </summary>
public sealed class AutorunScanner
{
    private static readonly string WinDir =
        Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLowerInvariant();

    private static readonly (RegistryHive Hive, RegistryView View, string Path, string Label)[] RunKeys =
    {
        (RegistryHive.CurrentUser,  RegistryView.Registry64, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",     @"HKCU\Run"),
        (RegistryHive.CurrentUser,  RegistryView.Registry64, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", @"HKCU\RunOnce"),
        (RegistryHive.LocalMachine, RegistryView.Registry64, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",     @"HKLM\Run"),
        (RegistryHive.LocalMachine, RegistryView.Registry64, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", @"HKLM\RunOnce"),
        (RegistryHive.LocalMachine, RegistryView.Registry32, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",     @"HKLM\Run (32)"),
    };

    public IReadOnlyList<AutorunEntry> Scan()
    {
        var list = new List<AutorunEntry>();
        foreach (var (hive, view, path, label) in RunKeys)
            ReadRunKey(hive, view, path, label, list);

        ReadStartupFolder(Environment.GetFolderPath(Environment.SpecialFolder.Startup), "بدء تشغيل المستخدم", list);
        ReadStartupFolder(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), "بدء تشغيل النظام", list);

        foreach (var e in list) Score(e);
        return list;
    }

    private static void ReadRunKey(RegistryHive hive, RegistryView view, string path, string label, List<AutorunEntry> list)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, view);
            using var key = baseKey.OpenSubKey(path);
            if (key is null) return;
            foreach (var name in key.GetValueNames())
            {
                string command = key.GetValue(name)?.ToString() ?? "";
                if (command.Length == 0) continue;
                list.Add(new AutorunEntry
                {
                    Name = name,
                    Location = label,
                    Command = command,
                    ImagePath = ResolveExe(command),
                });
            }
        }
        catch { /* key missing or access denied */ }
    }

    private static void ReadStartupFolder(string folder, string label, List<AutorunEntry> list)
    {
        try
        {
            if (string.IsNullOrEmpty(folder) || !Directory.Exists(folder)) return;
            foreach (var file in Directory.EnumerateFiles(folder))
            {
                if (Path.GetFileName(file).Equals("desktop.ini", StringComparison.OrdinalIgnoreCase))
                    continue;
                string? target = file.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase)
                    ? ResolveShortcut(file) ?? file
                    : file;
                list.Add(new AutorunEntry
                {
                    Name = Path.GetFileNameWithoutExtension(file),
                    Location = label,
                    Command = target,
                    ImagePath = target,
                });
            }
        }
        catch { }
    }

    // Pull the executable out of a registered command line: honour quotes, else stop at .exe,
    // else take the first token; expand %ENV% along the way.
    private static string? ResolveExe(string command)
    {
        string cmd = command.Trim();
        if (cmd.Length == 0) return null;
        string path;
        if (cmd[0] == '"')
        {
            int end = cmd.IndexOf('"', 1);
            path = end > 0 ? cmd[1..end] : cmd[1..];
        }
        else
        {
            int exe = cmd.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
            path = exe > 0 ? cmd[..(exe + 4)] : cmd.Split(' ', 2)[0];
        }
        path = Environment.ExpandEnvironmentVariables(path).Trim();
        return path.Length > 0 ? path : null;
    }

    // Resolve a .lnk to its target via WScript.Shell (present on every Windows box).
    private static string? ResolveShortcut(string lnk)
    {
        try
        {
            var t = Type.GetTypeFromProgID("WScript.Shell");
            if (t is null) return null;
            dynamic shell = Activator.CreateInstance(t)!;
            dynamic sc = shell.CreateShortcut(lnk);
            string target = sc.TargetPath;
            return string.IsNullOrEmpty(target) ? null : target;
        }
        catch { return null; }
    }

    private void Score(AutorunEntry e)
    {
        string? path = e.ImagePath;
        if (string.IsNullOrEmpty(path))
        {
            e.Verdict = Verdict.Review;
            e.Reason = "تعذّر تحديد الملف المستهدف";
            return;
        }
        if (!File.Exists(path))
        {
            e.Verdict = Verdict.Suspicious;
            e.Reason = "الملف المستهدف غير موجود";
            return;
        }

        var (state, publisher) = SignatureCache.Get(path);
        e.Signature = state;
        e.Publisher = publisher;

        string low = path.ToLowerInvariant();
        bool inSystem = low.StartsWith(WinDir) || low.Contains(@"\program files");
        bool inTemp = low.Contains(@"\temp\") || low.Contains(@"\appdata\local\temp");

        switch (state)
        {
            case SignatureState.SignedInvalid:
                e.Verdict = Verdict.Suspicious;
                e.Reason = "توقيع رقمي غير صالح";
                break;
            case SignatureState.Unsigned when inTemp:
                e.Verdict = Verdict.Suspicious;
                e.Reason = "غير موقّع ويعمل من مجلد مؤقّت";
                break;
            case SignatureState.Unsigned when !inSystem:
                e.Verdict = Verdict.Review;
                e.Reason = "غير موقّع خارج مجلدات النظام";
                break;
            case SignatureState.Unsigned:
                e.Verdict = Verdict.Review;
                e.Reason = "غير موقّع";
                break;
            default:
                e.Verdict = Verdict.Safe;
                e.Reason = "موقّع";
                break;
        }
    }
}
