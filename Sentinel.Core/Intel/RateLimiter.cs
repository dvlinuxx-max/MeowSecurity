using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Sentinel.Core.Intel;

/// <summary>
/// A sliding-window rate limiter so we never trip a provider's cap.
/// VirusTotal's free tier is 4 requests/minute and 500/day; this enforces both,
/// waiting (or refusing, in try-mode) instead of firing a request that would 429.
/// </summary>
public sealed class RateLimiter
{
    private readonly int _perMinute;
    private readonly int _perDay;
    private readonly Queue<DateTime> _minuteHits = new();
    private readonly Queue<DateTime> _dayHits = new();
    private readonly SemaphoreSlim _gate = new(1, 1);

    public RateLimiter(int perMinute, int perDay)
    {
        _perMinute = Math.Max(1, perMinute);
        _perDay = Math.Max(1, perDay);
    }

    /// <summary>True if a request could go out right now without blocking. Does not consume a slot.</summary>
    public bool CanProceedNow()
    {
        lock (_minuteHits)
        {
            Trim();
            return _minuteHits.Count < _perMinute && _dayHits.Count < _perDay;
        }
    }

    /// <summary>Acquire a slot, waiting up to <paramref name="maxWait"/>. Returns false if the daily cap is exhausted or the wait is too long.</summary>
    public async Task<bool> AcquireAsync(TimeSpan maxWait, CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var deadline = DateTime.UtcNow + maxWait;
            while (true)
            {
                TimeSpan wait;
                lock (_minuteHits)
                {
                    Trim();
                    if (_dayHits.Count >= _perDay)
                        return false; // daily quota gone — no amount of waiting helps today

                    if (_minuteHits.Count < _perMinute)
                    {
                        var now = DateTime.UtcNow;
                        _minuteHits.Enqueue(now);
                        _dayHits.Enqueue(now);
                        return true;
                    }

                    // Wait until the oldest hit in the minute window rolls off.
                    wait = _minuteHits.Peek().AddMinutes(1) - DateTime.UtcNow;
                }

                if (DateTime.UtcNow + wait > deadline) return false;
                if (wait > TimeSpan.Zero)
                    await Task.Delay(wait, ct).ConfigureAwait(false);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    private void Trim()
    {
        var now = DateTime.UtcNow;
        while (_minuteHits.Count > 0 && now - _minuteHits.Peek() > TimeSpan.FromMinutes(1))
            _minuteHits.Dequeue();
        while (_dayHits.Count > 0 && now - _dayHits.Peek() > TimeSpan.FromDays(1))
            _dayHits.Dequeue();
    }
}
