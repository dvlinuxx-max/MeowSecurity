using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Sentinel.Core.Intel;

/// <summary>
/// The single entry point the rest of Sentinel talks to for file reputation.
///
/// It layers the sources so the free, unmetered ones carry the load and the
/// metered one (VirusTotal) is only touched when the user opted in:
///   1. on-disk cache        — free, instant, most requests end here
///   2. CIRCL hashlookup     — keyless, unmetered, clears known-good files
///   3. MalwareBazaar        — free (with a free key), names known malware
///   4. VirusTotal           — opt-in, BYO-key, deep multi-engine verdict
///
/// The most severe verdict wins; a MalwareBazaar/VirusTotal "Malicious" always
/// overrides a CIRCL "KnownGood".
/// </summary>
public sealed class ThreatIntel : IDisposable
{
    private readonly IntelSettings _settings;
    private readonly HttpClient _http;
    private readonly IntelCache _cache;
    private readonly CirclHashlookup _circl;
    private readonly MalwareBazaarClient _bazaar;
    private readonly VirusTotalClient? _vt;
    private readonly AbuseIpdbClient? _abuseIpdb;

    public ThreatIntel(IntelSettings? settings = null)
    {
        _settings = settings ?? IntelSettings.Load();
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        _http.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", "Sentinel/1.0 (+security monitor)");

        _cache = new IntelCache();
        _circl = new CirclHashlookup(_http);
        _bazaar = new MalwareBazaarClient(_http, _settings.EffectiveAbuseChKey);
        if (_settings.HasVirusTotal)
            _vt = new VirusTotalClient(_http, _settings.EffectiveVirusTotalKey!);
        if (_settings.HasAbuseIpdb)
            _abuseIpdb = new AbuseIpdbClient(_http, _settings.EffectiveAbuseIpdbKey!);
    }

    public IntelSettings Settings => _settings;
    public bool VirusTotalReady => _vt is not null;
    public bool AbuseIpdbReady => _abuseIpdb is not null;

    /// <summary>Reputation for a file already identified by hash.</summary>
    public async Task<HashReputation> LookupHashAsync(string sha256, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(sha256))
            return HashReputation.UnknownFor(sha256 ?? "");

        if (_cache.TryGet(sha256, out var cached))
            return cached;

        if (!_settings.OnlineLookupsEnabled)
            return HashReputation.UnknownFor(sha256);

        var found = new List<HashReputation>();
        try
        {
            var circl = await _circl.LookupAsync(sha256, ct).ConfigureAwait(false);
            if (circl is not null) found.Add(circl);

            if (_bazaar.Available)
            {
                var mb = await _bazaar.LookupAsync(sha256, ct).ConfigureAwait(false);
                if (mb is not null) found.Add(mb);
            }

            if (_vt is not null)
            {
                var vt = await _vt.LookupHashAsync(sha256, ct).ConfigureAwait(false);
                if (vt is not null) found.Add(vt);
            }
        }
        catch (OperationCanceledException) { throw; }

        var merged = Merge(sha256, found);
        _cache.Put(merged);
        return merged;
    }

    /// <summary>Hash a file on disk, then look it up.</summary>
    public async Task<HashReputation> LookupFileAsync(string path, CancellationToken ct = default)
    {
        var sha = await FileHasher.Sha256Async(path, ct).ConfigureAwait(false);
        return sha is null ? HashReputation.UnknownFor("") : await LookupHashAsync(sha, ct).ConfigureAwait(false);
    }

    // ---- on-demand scans (require VirusTotal) ----

    public bool CanScan => _vt is not null;

    public Task<ScanReport> ScanFileAsync(string path, CancellationToken ct = default) =>
        _vt is null
            ? Task.FromResult(NoVt(path, ScanKind.File))
            : _vt.ScanFileAsync(path, ct);

    public Task<ScanReport> ScanUrlAsync(string url, CancellationToken ct = default) =>
        _vt is null
            ? Task.FromResult(NoVt(url, ScanKind.Url))
            : _vt.ScanUrlAsync(url, ct);

    public bool CanCheckIp => _abuseIpdb is not null;

    public Task<ScanReport> CheckIpAsync(string ip, CancellationToken ct = default) =>
        _abuseIpdb is null
            ? Task.FromResult(new ScanReport { Target = ip, Kind = ScanKind.Ip, Error = "أضف مفتاح AbuseIPDB في الإعدادات لفحص عناوين IP." })
            : _abuseIpdb.CheckAsync(ip, ct);

    /// <summary>
    /// One box, three targets: routes an IP to AbuseIPDB, a URL/domain to VirusTotal,
    /// and an existing file path to a VirusTotal file scan.
    /// </summary>
    public Task<ScanReport> AdvancedScanAsync(string input, CancellationToken ct = default)
    {
        var text = (input ?? "").Trim();
        if (text.Length == 0)
            return Task.FromResult(new ScanReport { Target = text, Kind = ScanKind.Url, Error = "أدخل رابطاً أو عنوان IP أو مساراً لملف." });

        if (System.Net.IPAddress.TryParse(text, out _))
            return CheckIpAsync(text, ct);

        if (System.IO.File.Exists(text))
            return ScanFileAsync(text, ct);

        // Treat anything with a dot and no spaces as a URL/domain; prefix scheme if missing.
        if (!text.Contains(' ') && text.Contains('.'))
        {
            if (!text.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
                !text.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                text = "http://" + text;
            return ScanUrlAsync(text, ct);
        }

        return Task.FromResult(new ScanReport { Target = text, Kind = ScanKind.Url, Error = "لم أتعرّف على المدخل — أدخل رابطاً أو IP أو مسار ملف." });
    }

    private static ScanReport NoVt(string target, ScanKind kind) => new()
    {
        Target = target,
        Kind = kind,
        Error = "أضف مفتاح VirusTotal في الإعدادات لتشغيل هذا الفحص.",
    };

    private static HashReputation Merge(string sha256, List<HashReputation> reps)
    {
        if (reps.Count == 0) return HashReputation.UnknownFor(sha256);

        // Highest severity wins; among equals, prefer the one with the richest detail (VT engine counts).
        var winner = reps
            .OrderByDescending(r => (int)r.Level)
            .ThenByDescending(r => r.TotalEngines)
            .First();

        // If a metered source confirmed malicious, keep its family/label even if another source is winner-tier.
        var malicious = reps.FirstOrDefault(r => r.Level == ThreatLevel.Malicious);
        if (malicious is not null && winner.Level == ThreatLevel.Malicious && winner.Family is null && malicious.Family is not null)
            winner = winner with { Family = malicious.Family };

        return winner;
    }

    public void Dispose() => _http.Dispose();
}
