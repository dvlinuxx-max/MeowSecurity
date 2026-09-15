using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Sentinel.Core.Intel;

/// <summary>
/// VirusTotal API v3 — opt-in, bring-your-own-key. Never shipped with a shared key,
/// so it can't blow a global quota. The free tier is 4 requests/minute and 500/day;
/// a <see cref="RateLimiter"/> enforces both so we degrade gracefully instead of 429-ing.
///
/// Hash lookups send only a hash. URL and file scans send the URL / file the user
/// explicitly chose to scan — surfaced clearly in the UI as an outbound action.
/// </summary>
public sealed class VirusTotalClient
{
    private const string Base = "https://www.virustotal.com/api/v3/";
    private const long MaxDirectUpload = 32L * 1024 * 1024; // VT's simple-upload ceiling

    private readonly HttpClient _http;
    private readonly string _apiKey;
    private readonly RateLimiter _limiter;

    public VirusTotalClient(HttpClient http, string apiKey, RateLimiter? limiter = null)
    {
        _http = http;
        _apiKey = apiKey;
        _limiter = limiter ?? new RateLimiter(perMinute: 4, perDay: 500);
    }

    /// <summary>How many requests could still go out right now without waiting.</summary>
    public bool QuotaAvailableNow => _limiter.CanProceedNow();

    // ---- passive hash reputation (used by the process view) ----

    public async Task<HashReputation?> LookupHashAsync(string sha256, CancellationToken ct = default)
    {
        if (!await _limiter.AcquireAsync(TimeSpan.FromSeconds(20), ct).ConfigureAwait(false))
            return null; // quota tapped out — CIRCL still covered us, so stay quiet

        try
        {
            using var req = Build(HttpMethod.Get, "files/" + sha256);
            using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
            if (resp.StatusCode == HttpStatusCode.NotFound) return null;
            if (!resp.IsSuccessStatusCode) return null;

            await using var stream = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct).ConfigureAwait(false);
            var (mal, susp, harm, undet, label) = ReadStats(doc.RootElement, "data");

            var level = mal > 0 ? ThreatLevel.Malicious
                      : susp > 0 ? ThreatLevel.Suspicious
                      : ThreatLevel.KnownGood;

            return new HashReputation
            {
                Sha256 = sha256,
                Level = level,
                Source = "VirusTotal",
                Family = label,
                Detections = mal + susp,
                TotalEngines = mal + susp + harm + undet,
                Detail = $"{mal + susp}/{mal + susp + harm + undet} engines" + (label is not null ? $" — {label}" : ""),
                Permalink = $"https://www.virustotal.com/gui/file/{sha256}",
            };
        }
        catch (OperationCanceledException) { throw; }
        catch { return null; }
    }

    // ---- on-demand scans (the Scan page) ----

    public async Task<ScanReport> ScanUrlAsync(string url, CancellationToken ct = default)
    {
        if (!await _limiter.AcquireAsync(TimeSpan.FromSeconds(20), ct).ConfigureAwait(false))
            return Fail(url, ScanKind.Url, "VirusTotal daily quota reached — try again later.");

        try
        {
            using var submit = Build(HttpMethod.Post, "urls");
            submit.Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["url"] = url });
            using var subResp = await _http.SendAsync(submit, ct).ConfigureAwait(false);
            if (!subResp.IsSuccessStatusCode)
                return Fail(url, ScanKind.Url, $"VirusTotal rejected the URL ({(int)subResp.StatusCode}).");

            var analysisId = await ReadAnalysisId(subResp, ct).ConfigureAwait(false);
            if (analysisId is null) return Fail(url, ScanKind.Url, "VirusTotal did not return an analysis id.");

            return await PollAnalysis(url, ScanKind.Url, analysisId,
                permalink: $"https://www.virustotal.com/gui/url/{UrlId(url)}", ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { return Fail(url, ScanKind.Url, ex.Message); }
    }

    public async Task<ScanReport> ScanFileAsync(string path, CancellationToken ct = default)
    {
        var sha = await FileHasher.Sha256Async(path, ct).ConfigureAwait(false);
        if (sha is null) return Fail(path, ScanKind.File, "Could not read the file to hash it.");

        // Cheapest path first: a report may already exist for this exact file.
        var existing = await LookupHashAsync(sha, ct).ConfigureAwait(false);
        if (existing is not null && existing.TotalEngines > 0)
            return FromHash(path, existing);

        var info = new FileInfo(path);
        if (!info.Exists) return Fail(path, ScanKind.File, "File no longer exists.");
        if (info.Length > MaxDirectUpload)
            return Fail(path, ScanKind.File, "File is larger than VirusTotal's 32 MB upload limit.");

        if (!await _limiter.AcquireAsync(TimeSpan.FromSeconds(20), ct).ConfigureAwait(false))
            return Fail(path, ScanKind.File, "VirusTotal daily quota reached — try again later.");

        try
        {
            using var content = new MultipartFormDataContent();
            await using var fs = File.OpenRead(path);
            content.Add(new StreamContent(fs), "file", Path.GetFileName(path));

            using var upload = Build(HttpMethod.Post, "files");
            upload.Content = content;
            using var upResp = await _http.SendAsync(upload, ct).ConfigureAwait(false);
            if (!upResp.IsSuccessStatusCode)
                return Fail(path, ScanKind.File, $"VirusTotal upload failed ({(int)upResp.StatusCode}).");

            var analysisId = await ReadAnalysisId(upResp, ct).ConfigureAwait(false);
            if (analysisId is null) return Fail(path, ScanKind.File, "VirusTotal did not return an analysis id.");

            return await PollAnalysis(path, ScanKind.File, analysisId,
                permalink: $"https://www.virustotal.com/gui/file/{sha}", ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { return Fail(path, ScanKind.File, ex.Message); }
    }

    // ---- plumbing ----

    private async Task<ScanReport> PollAnalysis(string target, ScanKind kind, string analysisId, string permalink, CancellationToken ct)
    {
        for (var attempt = 0; attempt < 20; attempt++)
        {
            await Task.Delay(TimeSpan.FromSeconds(attempt == 0 ? 3 : 6), ct).ConfigureAwait(false);
            if (!await _limiter.AcquireAsync(TimeSpan.FromSeconds(20), ct).ConfigureAwait(false))
                return Fail(target, kind, "VirusTotal quota reached while waiting for results.");

            using var req = Build(HttpMethod.Get, "analyses/" + analysisId);
            using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode) continue;

            await using var stream = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct).ConfigureAwait(false);
            var attrs = doc.RootElement.GetProperty("data").GetProperty("attributes");
            var status = attrs.TryGetProperty("status", out var st) ? st.GetString() : null;
            if (status != "completed") continue;

            var (mal, susp, harm, undet, _) = ReadStatsFromAttributes(attrs);
            var level = mal > 0 ? ThreatLevel.Malicious
                      : susp > 0 ? ThreatLevel.Suspicious
                      : ThreatLevel.KnownGood;

            return new ScanReport
            {
                Target = target,
                Kind = kind,
                Level = level,
                Malicious = mal,
                Suspicious = susp,
                Harmless = harm,
                Undetected = undet,
                Detail = $"{mal + susp}/{mal + susp + harm + undet} engines flagged this",
                Permalink = permalink,
            };
        }
        return Fail(target, kind, "VirusTotal analysis timed out.");
    }

    private HttpRequestMessage Build(HttpMethod method, string relative)
    {
        var req = new HttpRequestMessage(method, Base + relative);
        req.Headers.TryAddWithoutValidation("x-apikey", _apiKey);
        req.Headers.TryAddWithoutValidation("Accept", "application/json");
        return req;
    }

    private static async Task<string?> ReadAnalysisId(HttpResponseMessage resp, CancellationToken ct)
    {
        await using var stream = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct).ConfigureAwait(false);
        return doc.RootElement.TryGetProperty("data", out var data) && data.TryGetProperty("id", out var id)
            ? id.GetString()
            : null;
    }

    private static (int mal, int susp, int harm, int undet, string? label) ReadStats(JsonElement root, string dataProp)
    {
        var attrs = root.GetProperty(dataProp).GetProperty("attributes");
        return ReadStatsFromAttributes(attrs);
    }

    private static (int mal, int susp, int harm, int undet, string? label) ReadStatsFromAttributes(JsonElement attrs)
    {
        int mal = 0, susp = 0, harm = 0, undet = 0;
        var statsProp = attrs.TryGetProperty("last_analysis_stats", out var s1) ? s1
                      : attrs.TryGetProperty("stats", out var s2) ? s2 : default;
        if (statsProp.ValueKind == JsonValueKind.Object)
        {
            mal = GetInt(statsProp, "malicious");
            susp = GetInt(statsProp, "suspicious");
            harm = GetInt(statsProp, "harmless");
            undet = GetInt(statsProp, "undetected");
        }

        string? label = null;
        if (attrs.TryGetProperty("popular_threat_classification", out var cls) &&
            cls.TryGetProperty("suggested_threat_label", out var lbl))
            label = lbl.GetString();

        return (mal, susp, harm, undet, label);
    }

    private static int GetInt(JsonElement obj, string name) =>
        obj.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetInt32() : 0;

    private static string UrlId(string url) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(url)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static ScanReport FromHash(string target, HashReputation rep) => new()
    {
        Target = target,
        Kind = ScanKind.File,
        Level = rep.Level,
        Malicious = rep.Detections,
        Undetected = Math.Max(0, rep.TotalEngines - rep.Detections),
        Family = rep.Family,
        Detail = rep.Detail,
        Permalink = rep.Permalink,
    };

    private static ScanReport Fail(string target, ScanKind kind, string error) =>
        new() { Target = target, Kind = kind, Error = error };
}
