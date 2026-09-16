namespace MeowSecurity.Core.Persistence;

/// <summary>
/// Registers the monitor to start with Windows.
///
/// A scheduled task rather than a Run key, for one reason that decides everything: the live
/// capture needs administrator rights, and a Run entry would start the app unelevated — so it
/// would come back after every reboot quietly missing the very events it exists to catch. A
/// task registered to run with highest privileges starts fully armed and, unlike a shortcut
/// with "run as administrator", raises no UAC prompt at every login.
///
/// Creating such a task itself requires administrator rights, which is honest: the user grants
/// the permission once, deliberately, instead of being asked forever.
/// </summary>
public static class StartupRegistration
{
    private const string TaskName = "Meow Security Monitor";

    // Task Scheduler constants, spelled out because the COM interop is late-bound.
    private const int LogonTrigger = 9;
    private const int ExecAction = 0;
    private const int RunLevelHighest = 1;
    private const int LogonInteractiveToken = 3;
    private const int CreateOrUpdate = 6;

    public static bool IsRegistered()
    {
        try
        {
            dynamic? service = Connect();
            if (service is null) return false;
            dynamic folder = service.GetFolder(@"\");
            foreach (dynamic task in folder.GetTasks(1))
                if (string.Equals((string)task.Name, TaskName, StringComparison.OrdinalIgnoreCase))
                    return true;
            return false;
        }
        catch { return false; }
    }

    public static ControlResult Register(string executablePath)
    {
        if (!File.Exists(executablePath))
            return ControlResult.Fail("لم يعثر على ملف البرنامج");

        try
        {
            dynamic? service = Connect();
            if (service is null) return ControlResult.Fail("خدمة جدولة المهام غير متاحة");

            string user = $"{Environment.UserDomainName}\\{Environment.UserName}";
            dynamic definition = service.NewTask(0);

            definition.RegistrationInfo.Description =
                "يشغل Meow Security مع بدء ويندوز بصلاحية كاملة حتى تعمل المراقبة اللحظية.";
            definition.RegistrationInfo.Author = "Meow Security";

            definition.Principal.UserId = user;
            definition.Principal.LogonType = LogonInteractiveToken;
            definition.Principal.RunLevel = RunLevelHighest;

            // A monitor must not be stopped by the settings that suit a maintenance job:
            // no time limit, and it runs on battery like anything else that protects you.
            definition.Settings.Enabled = true;
            definition.Settings.StartWhenAvailable = true;
            definition.Settings.DisallowStartIfOnBatteries = false;
            definition.Settings.StopIfGoingOnBatteries = false;
            definition.Settings.ExecutionTimeLimit = "PT0S";
            definition.Settings.MultipleInstances = 2;   // IgnoreNew: one monitor is enough

            dynamic trigger = definition.Triggers.Create(LogonTrigger);
            trigger.UserId = user;
            // Let the desktop finish appearing first; the monitor loses nothing by waiting.
            trigger.Delay = "PT15S";

            dynamic action = definition.Actions.Create(ExecAction);
            action.Path = executablePath;
            action.WorkingDirectory = Path.GetDirectoryName(executablePath);

            service.GetFolder(@"\").RegisterTaskDefinition(
                TaskName, definition, CreateOrUpdate, null, null, LogonInteractiveToken);

            return ControlResult.Success("سيعمل مع بدء ويندوز بصلاحية كاملة");
        }
        catch (UnauthorizedAccessException)
        {
            return ControlResult.Elevate("التسجيل يحتاج صلاحية المدير مرة واحدة");
        }
        catch (Exception ex)
        {
            return ex.Message.Contains("denied", StringComparison.OrdinalIgnoreCase) ||
                   ex.Message.Contains("0x80070005", StringComparison.OrdinalIgnoreCase)
                ? ControlResult.Elevate("التسجيل يحتاج صلاحية المدير مرة واحدة")
                : ControlResult.Fail(ex.Message);
        }
    }

    public static ControlResult Unregister()
    {
        try
        {
            dynamic? service = Connect();
            if (service is null) return ControlResult.Fail("خدمة جدولة المهام غير متاحة");

            service.GetFolder(@"\").DeleteTask(TaskName, 0);
            return ControlResult.Success("لن يعمل مع بدء ويندوز");
        }
        catch (Exception ex)
        {
            return ex.Message.Contains("denied", StringComparison.OrdinalIgnoreCase)
                ? ControlResult.Elevate("الإلغاء يحتاج صلاحية المدير")
                : ControlResult.Fail(ex.Message);
        }
    }

    private static dynamic? Connect()
    {
        var type = Type.GetTypeFromProgID("Schedule.Service");
        if (type is null) return null;
        dynamic service = Activator.CreateInstance(type)!;
        service.Connect();
        return service;
    }
}
