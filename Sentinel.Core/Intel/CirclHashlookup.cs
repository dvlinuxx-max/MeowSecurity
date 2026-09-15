using System;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Sentinel.Core.Intel;

/// <summary>
/// CIRCL hashlookup (hashlookup.circl.lu) — a keyless, unmetered public service
/// backed by NSRL and other known-file corpora. This is the workhorse that scales
/// to any number of users: it mostly answers "yes, this is a known legitimate file",
/// which lets Sentinel clear the vast majority of processes as safe with no quota cost.
///
/// Only a hash leaves the machine — never file contents.
/// </summary>
public sealed class CirclHashlookup
{
    private const string Base = "https://hashlookup.circl.lu/lookup/sha256/";
    private readonly HttpClient _http;

    public CirclHashlookup(HttpClient http) => _http = http;

    public async Task<HashReputation?> LookupAsync(string sha256, CancellationToken ct = default)
    {
        try
        {
            using var resp = await _http.GetAsync(Base + sha256.ToUpperInvariant(), ct).ConfigureAwait(false);
            if (resp.StatusCode == HttpStatusCode.NotFound)
                return null; // not a known file — say nothing, let other sources speak

            if (!resp.IsSuccessStatusCode)
                return null;

            await using var stream = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct).ConfigureAwait(false);
            var root = doc.RootElement;

            // A "message" field is how CIRCL signals "non existing" on some deployments.
            if (root.TryGetProperty("message", out _))
                return null;

            // Some records carry an explicit malicious flag; honour it.
            if (root.TryGetProperty("KnownMalicious", out var mal) &&
                mal.ValueKind is JsonValueKind.String or JsonValueKind.True &&
                !string.Equals(mal.ToString(), "false", StringComparison.OrdinalIgnoreCase))
            {
                return new HashReputation
                {
                    Sha256 = sha256,
                    Level = ThreatLevel.Malicious,
                    Source = "CIRCL",
                    Family = mal.ToString(),
                    Detail = $"Flagged malicious by CIRCL ({mal})",
                };
            }

            var name = root.TryGetProperty("FileName", out var fn) ? fn.GetString() : null;
            var src = root.TryGetProperty("source", out var s) ? s.GetString()
                    : root.TryGetProperty("hashlookup:source", out var s2) ? s2.GetString() : null;

            return new HashReputation
            {
                Sha256 = sha256,
                Level = ThreatLevel.KnownGood,
                Source = "CIRCL",
                Detail = name is not null
                    ? $"Known good file: {name}" + (src is not null ? $" ({src})" : "")
                    : "Known good file (NSRL)",
            };
        }
        catch (OperationCanceledException) { throw; }
        catch
        {
            return null; // network hiccup — treat as "no opinion", never as a threat
        }
    }
}
