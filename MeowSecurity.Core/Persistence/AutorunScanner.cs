using Microsoft.Win32;
using MeowSecurity.Core.Intel;
using MeowSecurity.Core.Processes;

using MeowSecurity.Core.Localization;

namespace MeowSecurity.Core.Persistence;

/// <summary>
/// Enumerates everything Windows will launch without being asked — Run/RunOnce keys (per-user
/// and machine, including the 32-bit view), the Startup folders, auto-start services and
/// drivers, and scheduled tasks — resolves each to its target executable, and signature-checks
/// it. Unsigned or temp-folder autoruns are exactly the persistence footholds malware leaves
/// behind, so they are surfaced, not hidden.
///
/// Run keys alone stopped being enough a long time ago: services and scheduled tasks are what
/// actual intrusions use, because they survive a reboot, run before or without a login, and
/// nobody thinks to look at them.
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

        ReadStartupFolder(Environment.GetFolderPath(Environment.SpecialFolder.Startup), Strings.T("autorun.user-startup"), list);
        ReadStartupFolder(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), Strings.T("autorun.system-startup"), list);

        ReadServices(list);
        ReadScheduledTasks(list);

        foreach (var e in list) Score(e);
        return list;
    }

    /// <summary>
    /// Auto-starting services and drivers, straight from the registry rather than the service
    /// manager, so a service hidden from the SCM by a rootkit still shows up here.
    ///
    /// Start: 0 boot, 1 system, 2 automatic — those launch themselves. 3 (manual) and 4
    /// (disabled) wait to be asked, so they are not autoruns and would only add noise.
    /// </summary>
    private static void ReadServices(List<AutorunEntry> list)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var services = baseKey.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            if (services is null) return;

            foreach (var name in services.GetSubKeyNames())
            {
                try
                {
                    using var key = services.OpenSubKey(name);
                    if (key is null) continue;
                    if (key.GetValue("Start") is not int start) continue;
                    // Manual and disabled services are not autoruns, so they would only add
                    // noise — except the ones we switched off, which must stay visible or the
                    // user has no way to switch them back on.
                    if (start > 2 && !AutorunControl.WasDisabledByUs(name)) continue;

                    string command = key.GetValue("ImagePath")?.ToString() ?? "";
                    if (command.Length == 0) continue;

                    int type = key.GetValue("Type") as int? ?? 0;
                    bool driver = (type & 0x3) != 0;   // 1 kernel driver, 2 file-system driver
                    string? exe = ResolveExe(NormalizeNtPath(command));

                    // A shared-host service runs no binary of its own: svchost.exe is just the
                    // container, and the code that actually runs is the ServiceDll. That
                    // indirection is precisely why attackers register services this way.
                    if (exe is not null &&
                        Path.GetFileName(exe).Equals("svchost.exe", StringComparison.OrdinalIgnoreCase))
                    {
                        using var parameters = key.OpenSubKey("Parameters");
                        if (parameters?.GetValue("ServiceDll")?.ToString() is { Length: > 0 } dll)
                        {
                            exe = NormalizeNtPath(Environment.ExpandEnvironmentVariables(dll));
                            command = dll;
                        }
                    }

                    list.Add(new AutorunEntry
                    {
                        Name = key.GetValue("DisplayName")?.ToString() is { Length: > 0 } d && !d.StartsWith('@')
                            ? d : name,
                        Location = driver ? Strings.T("autorun.driver") : Strings.T("autorun.service"),
                        Command = command,
                        ImagePath = exe,
                        Kind = AutorunKind.Service,
                        ServiceName = name,
                        Enabled = start <= 2,
                    });
                }
                catch { /* one unreadable service must not sink the scan */ }
            }
        }
        catch { }
    }

    /// <summary>
    /// Scheduled tasks, through the Task Scheduler COM service — the same source the built-in
    /// tools read, so a task registered outside the Tasks folder is not missed. Only enabled
    /// tasks with an executable action can actually start something.
    /// </summary>
    private static void ReadScheduledTasks(List<AutorunEntry> list)
    {
        try
        {
            var type = Type.GetTypeFromProgID("Schedule.Service");
            if (type is null) return;
            dynamic service = Activator.CreateInstance(type)!;
            service.Connect();
            WalkTaskFolder(service.GetFolder(@"\"), list);
        }
        catch { /* service disabled or COM unavailable */ }
    }

    private static void WalkTaskFolder(dynamic folder, List<AutorunEntry> list, int depth = 0)
    {
        if (depth > 6) return;   // the built-in tree is three deep; this is a loop guard

        try
        {
            foreach (dynamic task in folder.GetTasks(1))   // 1 = include hidden tasks
            {
                try
                {
                    bool enabled = task.Enabled;
                    foreach (dynamic action in task.Definition.Actions)
                    {
                        if (action.Type != 0) continue;    // TASK_ACTION_EXEC
                        string path = action.Path as string ?? "";
                        if (path.Length == 0) continue;
                        string args = action.Arguments as string ?? "";

                        string full = Environment.ExpandEnvironmentVariables(path).Trim('"');
                        list.Add(new AutorunEntry
                        {
                            Name = task.Name,
                            Location = Strings.T("autorun.task"),
                            Command = args.Length > 0 ? $"{full} {args}" : full,
                            ImagePath = Path.IsPathRooted(full) ? full : ResolveExe(full),
                            Kind = AutorunKind.ScheduledTask,
                            TaskPath = task.Path,
                            Enabled = enabled,
                        });
                    }
                }
                catch { /* a task whose definition we may not read */ }
            }

            foreach (dynamic sub in folder.GetFolders(0))
                WalkTaskFolder(sub, list, depth + 1);
        }
        catch { }
    }

    /// <summary>
    /// Registry image paths are not plain Win32 paths: drivers use the native "\??\C:\..." or
    /// "\SystemRoot\..." forms, and many are relative to the Windows directory.
    /// </summary>
    private static string NormalizeNtPath(string path)
    {
        string p = path.Trim();
        if (p.StartsWith(@"\??\", StringComparison.Ordinal)) p = p[4..];
        if (p.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            p = Path.Combine(WinDirOriginal, p[12..]);
        else if (p.StartsWith(@"system32\", StringComparison.OrdinalIgnoreCase) ||
                 p.StartsWith(@"syswow64\", StringComparison.OrdinalIgnoreCase))
            p = Path.Combine(WinDirOriginal, p);
        return p;
    }

    private static readonly string WinDirOriginal =
        Environment.GetFolderPath(Environment.SpecialFolder.Windows);

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
                    Kind = AutorunKind.RunKey,
                    Hive = hive,
                    View = view,
                    KeyPath = path,
                    ValueName = name,
                    Enabled = AutorunControl.IsRunEntryApproved(hive, name),
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
                    Kind = AutorunKind.StartupFolder,
                    ItemPath = file,
                    Enabled = AutorunControl.IsStartupItemApproved(Path.GetFileName(file)),
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
        if (path.Length == 0) return null;
        return Path.IsPathRooted(path) ? path : ResolveOnPath(path);
    }

    /// <summary>
    /// Windows lets an autorun name a bare executable ("sc.exe") and finds it the same way
    /// CreateProcess would. Several built-in scheduled tasks do exactly that, so without this
    /// they all read as "target file missing" — false alarms on the shipping OS, which is the
    /// fastest way to teach someone to ignore this page.
    /// </summary>
    private static string? ResolveOnPath(string name)
    {
        var dirs = new List<string>
        {
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            Environment.GetFolderPath(Environment.SpecialFolder.SystemX86),
            WinDirOriginal,
        };
        dirs.AddRange((Environment.GetEnvironmentVariable("PATH") ?? "")
            .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));

        foreach (var dir in dirs)
        {
            try
            {
                if (dir.Length == 0) continue;
                string candidate = Path.Combine(dir, name);
                if (File.Exists(candidate)) return candidate;
                if (!Path.HasExtension(candidate) && File.Exists(candidate + ".exe"))
                    return candidate + ".exe";
            }
            catch { /* a malformed PATH entry */ }
        }
        return name;   // unresolved: let the scorer report it as missing
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
        // Persistence that runs a *trusted* tool is the harder case: the binary is signed by
        // Microsoft and passes every file check, and the attack lives entirely in the command
        // line. Judge that first, because it outranks anything the signature can tell us.
        if (LolbinRules.SuspiciousCommandLine(e.Command) is { } tell &&
            !tell.Equals("in-line remote download", StringComparison.Ordinal))
        {
            e.Verdict = Verdict.Suspicious;
            e.Reason = Strings.T("autorun.bad-command", tell);
            if (e.ImagePath is { Length: > 0 } p && File.Exists(p))
            {
                var (st, pub) = SignatureCache.Get(p);
                e.Signature = st;
                e.Publisher = pub;
            }
            return;
        }

        string? path = e.ImagePath;
        if (string.IsNullOrEmpty(path))
        {
            e.Verdict = Verdict.Review;
            e.Reason = Strings.T("autorun.no-target");
            return;
        }
        if (!File.Exists(path))
        {
            e.Verdict = Verdict.Suspicious;
            e.Reason = Strings.T("autorun.target-missing");
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
                e.Reason = Strings.T("autorun.bad-signature");
                break;
            case SignatureState.Unsigned when inTemp:
                e.Verdict = Verdict.Suspicious;
                e.Reason = Strings.T("autorun.unsigned-temp");
                break;
            case SignatureState.Unsigned when !inSystem:
                e.Verdict = Verdict.Review;
                e.Reason = Strings.T("autorun.unsigned-out");
                break;
            case SignatureState.Unsigned:
                e.Verdict = Verdict.Review;
                e.Reason = Strings.T("autorun.unsigned");
                break;
            default:
                e.Verdict = Verdict.Safe;
                e.Reason = Strings.T("autorun.signed");
                break;
        }
    }
}
