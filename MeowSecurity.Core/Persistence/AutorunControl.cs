using System.Text.Json;
using Microsoft.Win32;
using MeowSecurity.Core.Intel;

namespace MeowSecurity.Core.Persistence;

/// <summary>What happened when the user asked to change an autorun.</summary>
public sealed record ControlResult(bool Ok, string Message, bool NeedsElevation = false)
{
    public static ControlResult Success(string message) => new(true, message);
    public static ControlResult Fail(string message) => new(false, message);
    public static ControlResult Elevate(string message) => new(false, message, NeedsElevation: true);
}

/// <summary>
/// Turning an autorun off, and back on again.
///
/// Reporting a bad autorun and then leaving the user to open regedit is half a feature, so
/// this switches entries off the way Windows itself does — which matters for two reasons.
/// The state lands where Task Manager's Startup tab reads it, so the machine agrees with
/// itself, and nothing is destroyed, so every change here can be undone. Deletion exists too,
/// but it is a separate, deliberate act and it keeps a copy of what it removed.
///
/// Run keys and Startup-folder items: the StartupApproved flags, the same store Task Manager
/// writes (12 bytes; the first is 2 for enabled, 3 for disabled).
/// Scheduled tasks: the task's own Enabled flag, through the Task Scheduler service.
/// Services: the Start value, 4 meaning disabled. This one needs administrator rights.
/// </summary>
public static class AutorunControl
{
    private const string ApprovedRun =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
    private const string ApprovedStartupFolder =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder";

    private static readonly byte[] EnabledFlag = [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    private static readonly byte[] DisabledFlag = [3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    // ---------------- reading current state ----------------

    public static bool IsRunEntryApproved(RegistryHive hive, string valueName) =>
        IsApproved(hive, ApprovedRun, valueName);

    public static bool IsStartupItemApproved(string fileName) =>
        IsApproved(RegistryHive.CurrentUser, ApprovedStartupFolder, fileName) &&
        IsApproved(RegistryHive.LocalMachine, ApprovedStartupFolder, fileName);

    private static bool IsApproved(RegistryHive hive, string keyPath, string valueName)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
            using var key = baseKey.OpenSubKey(keyPath);
            // No entry at all means Windows has never been told to disable it.
            if (key?.GetValue(valueName) is not byte[] flag || flag.Length == 0) return true;
            return (flag[0] & 1) == 0;   // 2 = enabled, 3 = disabled
        }
        catch { return true; }
    }

    // ---------------- switching ----------------

    public static ControlResult SetEnabled(AutorunEntry entry, bool enable) => entry.Kind switch
    {
        AutorunKind.RunKey => SetApproval(entry.Hive, ApprovedRun, entry.ValueName, enable, entry),
        AutorunKind.StartupFolder => SetApproval(RegistryHive.CurrentUser, ApprovedStartupFolder,
            Path.GetFileName(entry.ItemPath), enable, entry),
        AutorunKind.ScheduledTask => SetTaskEnabled(entry, enable),
        AutorunKind.Service => SetServiceEnabled(entry, enable),
        _ => ControlResult.Fail("نوع غير مدعوم"),
    };

    private static ControlResult SetApproval(
        RegistryHive hive, string keyPath, string? valueName, bool enable, AutorunEntry entry)
    {
        if (string.IsNullOrEmpty(valueName)) return ControlResult.Fail("لا يمكن تحديد المدخل");
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
            using var key = baseKey.CreateSubKey(keyPath, writable: true);
            if (key is null) return ControlResult.Fail("تعذر فتح مفتاح السجل");

            key.SetValue(valueName, enable ? EnabledFlag : DisabledFlag, RegistryValueKind.Binary);
            entry.Enabled = enable;
            Remember(entry, enable ? null : "approval");
            return ControlResult.Success(enable ? "أعيد تفعيله" : "عطل — لن يعمل عند الإقلاع");
        }
        catch (UnauthorizedAccessException)
        {
            return ControlResult.Elevate("يحتاج صلاحية المدير لتعديل مدخل على مستوى الجهاز");
        }
        catch (Exception ex) { return ControlResult.Fail(ex.Message); }
    }

    private static ControlResult SetTaskEnabled(AutorunEntry entry, bool enable)
    {
        if (string.IsNullOrEmpty(entry.TaskPath)) return ControlResult.Fail("لا يمكن تحديد المهمة");
        try
        {
            var type = Type.GetTypeFromProgID("Schedule.Service");
            if (type is null) return ControlResult.Fail("خدمة جدولة المهام غير متاحة");
            dynamic service = Activator.CreateInstance(type)!;
            service.Connect();

            string folder = Path.GetDirectoryName(entry.TaskPath)?.Replace('\\', '\\') ?? "\\";
            if (string.IsNullOrEmpty(folder)) folder = "\\";
            dynamic task = service.GetFolder(folder).GetTask(Path.GetFileName(entry.TaskPath));
            task.Enabled = enable;

            entry.Enabled = enable;
            Remember(entry, enable ? null : "task");
            return ControlResult.Success(enable ? "أعيد تفعيل المهمة" : "عطلت المهمة المجدولة");
        }
        catch (UnauthorizedAccessException)
        {
            return ControlResult.Elevate("هذه المهمة تحتاج صلاحية المدير");
        }
        catch (Exception ex)
        {
            // The COM layer reports access denied as a plain COMException.
            return ex.Message.Contains("denied", StringComparison.OrdinalIgnoreCase)
                ? ControlResult.Elevate("هذه المهمة تحتاج صلاحية المدير")
                : ControlResult.Fail(ex.Message);
        }
    }

    private static ControlResult SetServiceEnabled(AutorunEntry entry, bool enable)
    {
        if (string.IsNullOrEmpty(entry.ServiceName)) return ControlResult.Fail("لا يمكن تحديد الخدمة");
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = baseKey.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{entry.ServiceName}", writable: true);
            if (key is null) return ControlResult.Fail("الخدمة غير موجودة");

            // 2 = automatic, 4 = disabled. Restoring to automatic is the safe default: a
            // service we disabled was auto-starting, or it would never have been listed.
            key.SetValue("Start", enable ? 2 : 4, RegistryValueKind.DWord);
            entry.Enabled = enable;
            Remember(entry, enable ? null : "service");
            return ControlResult.Success(enable
                ? "أعيد تفعيل الخدمة — تعمل بعد إعادة التشغيل"
                : "عطلت الخدمة — تتوقف بعد إعادة التشغيل");
        }
        catch (UnauthorizedAccessException)
        {
            return ControlResult.Elevate("تعطيل خدمة يحتاج صلاحية المدير");
        }
        catch (Exception ex) { return ControlResult.Fail(ex.Message); }
    }

    // ---------------- deletion ----------------

    /// <summary>
    /// Removes the entry outright. Only for the registry values and shortcuts we can restore
    /// from the copy taken here — a service or a task is disabled, never deleted, because
    /// rebuilding one from a backup file is not something this tool should promise.
    /// </summary>
    public static ControlResult Remove(AutorunEntry entry)
    {
        try
        {
            switch (entry.Kind)
            {
                case AutorunKind.RunKey:
                {
                    using var baseKey = RegistryKey.OpenBaseKey(entry.Hive, entry.View);
                    using var key = baseKey.OpenSubKey(entry.KeyPath!, writable: true);
                    if (key is null) return ControlResult.Fail("تعذر فتح مفتاح السجل");
                    Remember(entry, "removed");
                    key.DeleteValue(entry.ValueName!, throwOnMissingValue: false);
                    return ControlResult.Success("حذف المدخل من السجل");
                }
                case AutorunKind.StartupFolder:
                {
                    if (entry.ItemPath is null || !File.Exists(entry.ItemPath))
                        return ControlResult.Fail("الملف غير موجود");
                    Remember(entry, "removed");
                    File.Delete(entry.ItemPath);
                    return ControlResult.Success("حذف من مجلد بدء التشغيل");
                }
                default:
                    return ControlResult.Fail("الخدمات والمهام تعطل ولا تحذف");
            }
        }
        catch (UnauthorizedAccessException)
        {
            return ControlResult.Elevate("الحذف يحتاج صلاحية المدير");
        }
        catch (Exception ex) { return ControlResult.Fail(ex.Message); }
    }

    // ---------------- the undo record ----------------

    private sealed record Change(string Kind, string Name, string Location, string Command,
        string? Hive, string? KeyPath, string? ValueName, string? ItemPath,
        string? ServiceName, string? TaskPath, string Action, DateTime WhenUtc);

    private static string LogPath => Path.Combine(IntelSettings.ConfigDirectory, "autorun-changes.json");
    private static readonly object WriteLock = new();

    /// <summary>
    /// Writes down what was changed, so a mistake is recoverable and a disabled service can
    /// still be found. Passing null clears the record for an entry that was re-enabled.
    /// </summary>
    private static void Remember(AutorunEntry entry, string? action)
    {
        lock (WriteLock)
        {
            try
            {
                var all = LoadChanges();
                string id = Identity(entry);
                all.RemoveAll(c => Identity(c) == id);

                if (action is not null)
                    all.Add(new Change(entry.Kind.ToString(), entry.Name, entry.Location, entry.Command,
                        entry.Kind == AutorunKind.RunKey ? entry.Hive.ToString() : null,
                        entry.KeyPath, entry.ValueName, entry.ItemPath, entry.ServiceName, entry.TaskPath,
                        action, DateTime.UtcNow));

                Directory.CreateDirectory(IntelSettings.ConfigDirectory);
                File.WriteAllText(LogPath, JsonSerializer.Serialize(all,
                    new JsonSerializerOptions { WriteIndented = true }));
            }
            catch { /* the record is a convenience; never block the change itself */ }
        }
    }

    private static List<Change> LoadChanges()
    {
        try
        {
            return File.Exists(LogPath)
                ? JsonSerializer.Deserialize<List<Change>>(File.ReadAllText(LogPath)) ?? []
                : [];
        }
        catch { return []; }
    }

    private static string Identity(AutorunEntry e) =>
        $"{e.Kind}|{e.ServiceName}|{e.TaskPath}|{e.KeyPath}|{e.ValueName}|{e.ItemPath}";

    private static string Identity(Change c) =>
        $"{c.Kind}|{c.ServiceName}|{c.TaskPath}|{c.KeyPath}|{c.ValueName}|{c.ItemPath}";

    /// <summary>Did we disable this service? Keeps it on the list so it can be switched back.</summary>
    public static bool WasDisabledByUs(string serviceName)
    {
        try
        {
            return LoadChanges().Any(c =>
                c.Kind == nameof(AutorunKind.Service) &&
                string.Equals(c.ServiceName, serviceName, StringComparison.OrdinalIgnoreCase));
        }
        catch { return false; }
    }
}
