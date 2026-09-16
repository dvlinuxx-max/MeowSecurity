using Microsoft.Win32;
using MeowSecurity.Core.Processes;

namespace MeowSecurity.Core.Persistence;

/// <summary>Where an autorun comes from — which decides how it can be turned off.</summary>
public enum AutorunKind
{
    RunKey,
    StartupFolder,
    Service,
    ScheduledTask,
}

/// <summary>One thing Windows launches automatically — a registry Run value, a Startup-folder
/// shortcut, an auto-start service, a scheduled task. Persistence is where malware hides to
/// survive a reboot, so each entry is signature-checked and scored the same way a running
/// process is.
///
/// The identity fields below are what make an entry actionable rather than merely reportable:
/// without knowing exactly which value in which hive produced it, all we could ever do is
/// point at a problem and shrug.</summary>
public sealed class AutorunEntry
{
    public required string Name { get; init; }
    public required string Location { get; init; }   // e.g. "HKCU\Run", "مجلد بدء التشغيل"
    public required string Command { get; init; }    // raw command line as registered
    public string? ImagePath { get; init; }          // resolved executable
    public string? Publisher { get; set; }
    public SignatureState Signature { get; set; }
    public Verdict Verdict { get; set; }
    public string Reason { get; set; } = "";

    // ---- identity: enough to find this entry again and switch it off ----

    public AutorunKind Kind { get; init; }

    /// <summary>False when Windows is currently told not to launch it.</summary>
    public bool Enabled { get; set; } = true;

    // RunKey
    public RegistryHive Hive { get; init; }
    public RegistryView View { get; init; }
    public string? KeyPath { get; init; }
    public string? ValueName { get; init; }

    /// <summary>StartupFolder: the shortcut or executable sitting in the folder.</summary>
    public string? ItemPath { get; init; }

    /// <summary>Service: the registry key name, which is the service's real name.</summary>
    public string? ServiceName { get; init; }

    /// <summary>ScheduledTask: full path in the task tree, e.g. "\Microsoft\Windows\Foo\Bar".</summary>
    public string? TaskPath { get; init; }
}
