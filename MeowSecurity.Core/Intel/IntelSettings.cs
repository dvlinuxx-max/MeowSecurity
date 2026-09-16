using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace MeowSecurity.Core.Intel;

/// <summary>
/// The user's preferences, and the only thing this application persists.
///
/// Meow Security works entirely offline: it sends nothing anywhere, so there are no keys,
/// accounts or endpoints to configure. What is kept here is the handful of choices the
/// interface offers, written to %LOCALAPPDATA%\MeowSecurity\settings.json.
/// </summary>
public sealed class IntelSettings
{
    /// <summary>"dark" or "light".</summary>
    public string Theme { get; set; } = "light";

    /// <summary>Show a pop-up when a suspicious process appears.</summary>
    public bool Notifications { get; set; } = true;

    /// <summary>Also raise a Windows notification, so an alert is seen with the app in the background.</summary>
    public bool SystemNotifications { get; set; } = true;

    /// <summary>Play a sound with a serious alert.</summary>
    public bool AlertSound { get; set; } = true;

    /// <summary>Keep monitoring from the tray after the window is closed.</summary>
    public bool RunInBackground { get; set; } = false;

    /// <summary>Watch device health (CPU, memory) and flag sustained strain.</summary>
    public bool HealthMonitoring { get; set; } = true;

    // ---- persistence ----

    private static string? _configDirectory;

    /// <summary>
    /// Where settings and the event log live.
    ///
    /// The product was renamed, and a rename must not silently orphan someone's history, so
    /// the first call moves an existing folder from the old name across. It runs once per
    /// process and never overwrites a folder that is already there.
    /// </summary>
    public static string ConfigDirectory => _configDirectory ??= ResolveConfigDirectory();

    private static string ResolveConfigDirectory()
    {
        string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string current = Path.Combine(local, "MeowSecurity");
        string legacy = Path.Combine(local, "Sentinel");

        try
        {
            if (!Directory.Exists(current) && Directory.Exists(legacy))
                Directory.Move(legacy, current);
        }
        catch (IOException) { /* in use by another copy — carry on with the new folder */ }
        catch (UnauthorizedAccessException) { }

        return current;
    }

    public static string ConfigPath => Path.Combine(ConfigDirectory, "settings.json");

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static IntelSettings Load()
    {
        try
        {
            if (File.Exists(ConfigPath))
            {
                var json = File.ReadAllText(ConfigPath);
                return JsonSerializer.Deserialize<IntelSettings>(json, JsonOpts) ?? new IntelSettings();
            }
        }
        catch
        {
            // Corrupt or unreadable config never blocks startup — fall back to defaults.
        }
        return new IntelSettings();
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(ConfigDirectory);
            File.WriteAllText(ConfigPath, JsonSerializer.Serialize(this, JsonOpts));
        }
        catch
        {
            // Best effort — a read-only profile just means settings don't persist.
        }
    }
}
