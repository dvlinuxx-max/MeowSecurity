using System;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Sentinel.Core.Intel;

/// <summary>
/// AbuseIPDB (api.abuseipdb.com/api/v2) — IP address reputation, bring-your-own-key.
/// The free tier allows 1000 checks/day, so like VirusTotal it stays opt-in and keyed
/// to the user's own account. It answers "has this address been reported for abuse?"
/// with a 0-100 confidence score plus country/ISP context.
/// </summary>
public sealed class AbuseIpdbClient
{
    private const string Endpoint = "https://api.abuseipdb.com/api/v2/check";
    private readonly HttpClient _http;
    private readonly string _apiKey;
    private readonly RateLimiter _limiter;

    public AbuseIpdbClient(HttpClient http, string apiKey, RateLimiter? limiter = null)
    {
        _http = http;
        _apiKey = apiKey;
        // Generous relative to the daily cap; mainly guards against accidental bursts.
        _limiter = limiter ?? new RateLimiter(perMinute: 30, perDay: 1000);
    }

    public async Task<ScanReport> CheckAsync(string ip, CancellationToken ct = default)
    {
        if (!System.Net.IPAddress.TryParse(ip, out _))
            return new ScanReport { Target = ip, Kind = ScanKind.Ip, Error = "That doesn't look like an IP address." };

        if (!await _limiter.AcquireAsync(TimeSpan.FromSeconds(20), ct).ConfigureAwait(false))
            return new ScanReport { Target = ip, Kind = ScanKind.Ip, Error = "AbuseIPDB daily quota reached — try again later." };

        try
        {
            var url = $"{Endpoint}?ipAddress={Uri.EscapeDataString(ip)}&maxAgeInDays=90";
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            req.Headers.TryAddWithoutValidation("Key", _apiKey);
            req.Headers.TryAddWithoutValidation("Accept", "application/json");

            using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
                return new ScanReport { Target = ip, Kind = ScanKind.Ip, Error = $"AbuseIPDB error ({(int)resp.StatusCode})." };

            await using var stream = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct).ConfigureAwait(false);
            if (!doc.RootElement.TryGetProperty("data", out var data))
                return new ScanReport { Target = ip, Kind = ScanKind.Ip, Error = "AbuseIPDB returned no data." };

            int score = GetInt(data, "abuseConfidenceScore");
            int reports = GetInt(data, "totalReports");
            string? country = data.TryGetProperty("countryCode", out var c) ? c.GetString() : null;
            string? isp = data.TryGetProperty("isp", out var i) ? i.GetString() : null;

            var level = score >= 50 ? ThreatLevel.Malicious
                      : score >= 15 ? ThreatLevel.Suspicious
                      : ThreatLevel.KnownGood;

            return new ScanReport
            {
                Target = ip,
                Kind = ScanKind.Ip,
                Level = level,
                Source = "AbuseIPDB",
                AbuseScore = score,
                Reports = reports,
                Country = country,
                Isp = isp,
                Detail = $"درجة الإساءة {score}٪ · {reports} بلاغ" +
                         (country is not null ? $" · {country}" : "") +
                         (isp is not null ? $" · {isp}" : ""),
                Permalink = $"https://www.abuseipdb.com/check/{ip}",
            };
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            return new ScanReport { Target = ip, Kind = ScanKind.Ip, Error = ex.Message };
        }
    }

    private static int GetInt(JsonElement obj, string name) =>
        obj.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetInt32() : 0;
}
