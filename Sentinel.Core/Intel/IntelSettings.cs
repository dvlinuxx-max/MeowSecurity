using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Sentinel.Core.Intel;

/// <summary>
/// User-owned intel configuration, kept out of the app package on purpose.
///
/// The store build ships with NO embedded keys. Reputation for every user runs
/// through the keyless CIRCL hashlookup, so nothing here is required to get value.
/// VirusTotal is opt-in and bring-your-own-key: the key lives only in this file
/// under %LOCALAPPDATA%\Sentinel and is never transmitted anywhere except VT itself.
///
/// Resolution order for each key: explicit file value, then environment variable
/// (SENTINEL_VT_KEY / SENTINEL_ABUSECH_KEY) so CI and dev machines can inject one
/// without writing it to disk.
/// </summary>
public sealed class IntelSettings
{
    public string? VirusTotalApiKey { get; set; }
    public string? AbuseChApiKey { get; set; }
    public string? AbuseIpdbApiKey { get; set; }

    /// <summary>Master switch for any outbound reputation lookup. Off means fully offline.</summary>
    public bool OnlineLookupsEnabled { get; set; } = true;

    /// <summary>Allow sending file hashes to VirusTotal (only hashes, never file contents, unless the user explicitly uploads).</summary>
    public bool VirusTotalEnabled { get; set; } = false;

    // ---- interface preferences (persisted in the same file) ----

    /// <summary>"dark" or "light".</summary>
    public string Theme { get; set; } = "light";

    /// <summary>Show a pop-up when a suspicious or malicious process appears.</summary>
    public bool Notifications { get; set; } = true;

    /// <summary>Keep monitoring from the tray after the window is closed.</summary>
    public bool RunInBackground { get; set; } = false;

    /// <summary>Watch device health (CPU, memory, disk pressure) and flag sustained strain.</summary>
    public bool HealthMonitoring { get; set; } = true;

    [JsonIgnore]
    public string? EffectiveVirusTotalKey =>
        FirstNonEmpty(VirusTotalApiKey, Environment.GetEnvironmentVariable("SENTINEL_VT_KEY"));

    [JsonIgnore]
    public string? EffectiveAbuseChKey =>
        FirstNonEmpty(AbuseChApiKey, Environment.GetEnvironmentVariable("SENTINEL_ABUSECH_KEY"));

    [JsonIgnore]
    public string? EffectiveAbuseIpdbKey =>
        FirstNonEmpty(AbuseIpdbApiKey, Environment.GetEnvironmentVariable("SENTINEL_ABUSEIPDB_KEY"));

    [JsonIgnore]
    public bool HasVirusTotal => VirusTotalEnabled && !string.IsNullOrWhiteSpace(EffectiveVirusTotalKey);

    [JsonIgnore]
    public bool HasAbuseIpdb => !string.IsNullOrWhiteSpace(EffectiveAbuseIpdbKey);

    // ---- persistence ----

    private static string? _configDirectory;

    /// <summary>
    /// Where keys, cached verdicts and the event log live.
    ///
    /// The product was renamed, and a rename must not silently orphan someone's API keys and
    /// history, so the first call moves an existing folder from the old name across. It runs
    /// once per process and never overwrites a folder that is already there.
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

    private static string? FirstNonEmpty(params string?[] values)
    {
        foreach (var v in values)
            if (!string.IsNullOrWhiteSpace(v))
                return v.Trim();
        return null;
    }
}
