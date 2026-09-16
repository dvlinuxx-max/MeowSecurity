using MeowSecurity.Core.Detect;
using MeowSecurity.Core.Live;

namespace MeowSecurity.Core.Health;

/// <summary>
/// Watches the machine itself, not what is running on it.
///
/// Sustained strain is worth saying out loud for two reasons. It is the symptom people
/// actually notice — "my machine got slow" is why most users open a tool like this — and it is
/// how the quieter kinds of compromise show themselves: a miner, a stuck update, something
/// looping in the background at three in the morning.
///
/// The hard part is not measuring, it is not nagging. A spike while a build runs is normal, so
/// nothing is said until the strain has held for a full minute, and nothing is said again until
/// the machine has recovered. One line per episode, not one per tick.
/// </summary>
public sealed class HealthMonitor
{
    private const double CpuHighPercent = 90;
    private const double MemoryHighPercent = 90;
    private const double RecoveredPercent = 70;

    /// <summary>How long strain must hold before it is worth mentioning.</summary>
    private static readonly TimeSpan Sustained = TimeSpan.FromMinutes(1);

    private DateTime? _cpuHighSince;
    private DateTime? _memoryHighSince;
    private bool _cpuReported;
    private bool _memoryReported;

    /// <summary>
    /// Feeds one tick in and returns a finding only at the moment an episode becomes worth
    /// reporting. <paramref name="topProcess"/> names the heaviest consumer, which is the
    /// first thing anyone asks.
    /// </summary>
    public SecurityEvent? Observe(SystemPulse pulse, string? topProcess, DateTime now)
    {
        var cpu = Track(pulse.CpuPercent, CpuHighPercent, ref _cpuHighSince, ref _cpuReported, now);

        double memoryPercent = pulse.MemoryTotal > 0
            ? pulse.MemoryUsed * 100.0 / pulse.MemoryTotal
            : 0;
        var memory = Track(memoryPercent, MemoryHighPercent, ref _memoryHighSince, ref _memoryReported, now);

        if (cpu)
            return Make("health.cpu", "ضغط مستمر على المعالج",
                $"المعالج فوق {CpuHighPercent:0}% منذ أكثر من دقيقة" +
                (topProcess is null ? "." : $"، وأكثر عملية استهلاكا هي {topProcess}."),
                topProcess);

        if (memory)
            return Make("health.memory", "الذاكرة شبه ممتلئة",
                $"استهلاك الذاكرة فوق {MemoryHighPercent:0}% منذ أكثر من دقيقة" +
                (topProcess is null ? "." : $"، وأكثر عملية استهلاكا هي {topProcess}."),
                topProcess);

        return null;
    }

    /// <summary>Returns true exactly once per episode: when strain has held long enough.</summary>
    private static bool Track(double value, double threshold, ref DateTime? since, ref bool reported, DateTime now)
    {
        if (value >= threshold)
        {
            since ??= now;
            if (!reported && now - since >= Sustained)
            {
                reported = true;
                return true;
            }
            return false;
        }

        if (value < RecoveredPercent)
        {
            since = null;
            reported = false;   // recovered — a later episode may speak again
        }
        return false;
    }

    private static SecurityEvent Make(string rule, string title, string detail, string? process) =>
        new()
        {
            Severity = Severity.Medium,
            Score = 20,
            Pid = 0,
            Process = process ?? "النظام",
            Rule = rule,
            Title = title,
            Detail = detail,
            AllRules = [rule],
        };
}
