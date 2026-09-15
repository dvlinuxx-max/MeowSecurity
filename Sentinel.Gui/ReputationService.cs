using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Threading;
using Sentinel.Core.Intel;

namespace Sentinel.Gui;

/// <summary>
/// Fills in each process's reputation in the background, then colours its row and
/// raises an alert for anything flagged. Work is deduplicated by image path and
/// throttled so hashing a few hundred executables doesn't stall the UI or the disk.
/// </summary>
public sealed class ReputationService : IDisposable
{
    private readonly ThreatIntel _intel;
    private readonly Dispatcher _ui;
    private readonly Action<LiveRow, ThreatLevel> _onFlagged;

    private readonly BlockingCollection<LiveRow> _queue = new(new ConcurrentQueue<LiveRow>());
    private readonly HashSet<string> _queuedPaths = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, ThreatLevel> _resolved = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new();
    private readonly CancellationTokenSource _cts = new();

    public ReputationService(ThreatIntel intel, Dispatcher ui, Action<LiveRow, ThreatLevel> onFlagged)
    {
        _intel = intel;
        _ui = ui;
        _onFlagged = onFlagged;
        Task.Run(WorkerAsync);
    }

    /// <summary>Queue a row for a reputation check. Paths already resolved are applied at once.</summary>
    public void Enqueue(LiveRow row)
    {
        var path = row.ImagePath;
        if (string.IsNullOrEmpty(path)) return;

        lock (_lock)
        {
            if (_resolved.TryGetValue(path, out var known))
            {
                if (known != ThreatLevel.Unknown) Apply(row, known);
                return;
            }
            if (!_queuedPaths.Add(path)) return; // another row with this path is already in flight
        }

        try { _queue.Add(row); } catch { /* disposed */ }
    }

    private async Task WorkerAsync()
    {
        try
        {
            foreach (var row in _queue.GetConsumingEnumerable(_cts.Token))
            {
                var path = row.ImagePath;
                if (string.IsNullOrEmpty(path)) continue;

                ThreatLevel level;
                try
                {
                    var rep = await _intel.LookupFileAsync(path, _cts.Token).ConfigureAwait(false);
                    level = rep.Level;
                }
                catch (OperationCanceledException) { break; }
                catch { level = ThreatLevel.Unknown; }

                lock (_lock) _resolved[path] = level;
                if (level != ThreatLevel.Unknown) Apply(row, level);

                // Be gentle: a short pause keeps hashing and network calls off the UI's back.
                try { await Task.Delay(120, _cts.Token).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
            }
        }
        catch (OperationCanceledException) { /* shutting down */ }
    }

    private void Apply(LiveRow row, ThreatLevel level)
    {
        if (_ui.HasShutdownStarted) return;
        _ui.BeginInvoke(() =>
        {
            row.SetReputation(level);
            if (level is ThreatLevel.Malicious or ThreatLevel.Suspicious)
                _onFlagged(row, level);
        });
    }

    public void Dispose()
    {
        _cts.Cancel();
        _queue.CompleteAdding();
        _cts.Dispose();
    }
}
