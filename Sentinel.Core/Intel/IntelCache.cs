using System;
using System.Collections.Concurrent;
using System.IO;
using System.Text.Json;

namespace Sentinel.Core.Intel;

/// <summary>
/// A durable, SHA-256-keyed cache of reputation verdicts.
///
/// This is the piece that lets the app serve a large user base without burning
/// anybody's quota: the same svchost.exe, chrome.exe or malware sample is asked
/// about once, then answered from disk for a long time. Cache hits cost nothing.
///
/// Known-good verdicts (NSRL) essentially never change, so they live long.
/// Unknown verdicts expire quickly so a file that later gets classified is re-checked.
/// </summary>
public sealed class IntelCache
{
    private readonly string _path;
    private readonly ConcurrentDictionary<string, HashReputation> _mem = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _writeLock = new();

    public IntelCache(string? path = null)
    {
        _path = path ?? Path.Combine(IntelSettings.ConfigDirectory, "intel-cache.json");
        Load();
    }

    public bool TryGet(string sha256, out HashReputation rep)
    {
        if (_mem.TryGetValue(sha256, out var cached) && !IsStale(cached))
        {
            rep = cached with { Source = "cache" };
            return true;
        }
        rep = HashReputation.UnknownFor(sha256);
        return false;
    }

    public void Put(HashReputation rep)
    {
        // Don't persist "Unknown" — we want to retry those, and they'd just bloat the file.
        if (rep.Level == ThreatLevel.Unknown) return;
        _mem[rep.Sha256] = rep;
        Persist();
    }

    private static bool IsStale(HashReputation rep)
    {
        var age = DateTime.UtcNow - rep.AsOfUtc;
        return rep.Level switch
        {
            ThreatLevel.KnownGood => age > TimeSpan.FromDays(90),
            ThreatLevel.Malicious => age > TimeSpan.FromDays(30),
            ThreatLevel.Suspicious => age > TimeSpan.FromDays(7),
            _ => true,
        };
    }

    private void Load()
    {
        try
        {
            if (!File.Exists(_path)) return;
            var json = File.ReadAllText(_path);
            var items = JsonSerializer.Deserialize<HashReputation[]>(json);
            if (items is null) return;
            foreach (var it in items)
                if (!string.IsNullOrEmpty(it.Sha256))
                    _mem[it.Sha256] = it;
        }
        catch
        {
            // A corrupt cache is not worth crashing over — start empty.
        }
    }

    private void Persist()
    {
        lock (_writeLock)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
                var tmp = _path + ".tmp";
                File.WriteAllText(tmp, JsonSerializer.Serialize(_mem.Values));
                File.Move(tmp, _path, overwrite: true);
            }
            catch
            {
                // Best effort; an unwritable cache just means we look things up again next run.
            }
        }
    }
}
