using System.Text;
using System.Text.Json;
using MeowSecurity.Core.Intel;

namespace MeowSecurity.Core.Detect;

/// <summary>
/// The durable memory of the monitor: an append-only JSON-lines log of security events at
/// %LOCALAPPDATA%\MeowSecurity\events.jsonl.
///
/// JSON lines rather than one JSON array because appending must be O(1) and must never risk
/// the whole file: a torn write costs one line, and a corrupt line is skipped on load. The
/// file is trimmed to the newest <see cref="MaxEvents"/> entries when it grows past that, so
/// it stays small enough to load instantly at startup and can never fill a disk.
/// </summary>
public sealed class EventStore
{
    public const int MaxEvents = 2000;

    private readonly string _path;
    private readonly object _lock = new();
    private int _lineCount;

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = false };

    // No BOM: every line is parsed on its own, and a byte-order mark on the first one makes
    // that line — the oldest event in the file — fail to deserialize and silently vanish.
    private static readonly UTF8Encoding Utf8NoBom = new(encoderShouldEmitUTF8Identifier: false);

    public EventStore(string? path = null)
    {
        _path = path ?? System.IO.Path.Combine(IntelSettings.ConfigDirectory, "events.jsonl");
    }

    /// <summary>Where the log lives, so the settings page can show or open it.</summary>
    public string FilePath => _path;

    /// <summary>Newest first. Malformed lines are dropped rather than throwing.</summary>
    public List<SecurityEvent> Load(int limit = MaxEvents)
    {
        var events = new List<SecurityEvent>();
        lock (_lock)
        {
            if (!File.Exists(_path)) return events;
            try
            {
                var lines = File.ReadAllLines(_path);
                _lineCount = lines.Length;
                for (int i = lines.Length - 1; i >= 0 && events.Count < limit; i--)
                {
                    var line = lines[i].TrimStart('﻿').Trim();   // tolerate a legacy BOM
                    if (line.Length == 0) continue;
                    try
                    {
                        var ev = JsonSerializer.Deserialize<SecurityEvent>(line, Json);
                        if (ev is not null) events.Add(ev);
                    }
                    catch (JsonException) { /* torn or hand-edited line — skip it */ }
                }
            }
            catch (IOException) { /* locked by another instance — show what we have */ }
        }
        return events;
    }

    public void Append(SecurityEvent ev)
    {
        lock (_lock)
        {
            try
            {
                Directory.CreateDirectory(System.IO.Path.GetDirectoryName(_path)!);
                File.AppendAllText(_path, JsonSerializer.Serialize(ev, Json) + Environment.NewLine, Utf8NoBom);
                if (++_lineCount > MaxEvents + 500) Trim();
            }
            catch (IOException) { /* never let logging break monitoring */ }
            catch (UnauthorizedAccessException) { }
        }
    }

    public void Clear()
    {
        lock (_lock)
        {
            try { if (File.Exists(_path)) File.Delete(_path); _lineCount = 0; }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    // Rewrite keeping only the newest MaxEvents lines. Called rarely, so cost is irrelevant.
    private void Trim()
    {
        try
        {
            var lines = File.ReadAllLines(_path);
            if (lines.Length <= MaxEvents) { _lineCount = lines.Length; return; }
            var keep = lines[^MaxEvents..];
            var temp = _path + ".tmp";
            File.WriteAllLines(temp, keep, Utf8NoBom);
            File.Move(temp, _path, overwrite: true);
            _lineCount = keep.Length;
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }
}
