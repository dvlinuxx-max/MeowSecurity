using System.Text.Json.Serialization;

namespace Sentinel.Core.Detect;

/// <summary>
/// One thing worth remembering. A detection describes a rule firing; an event records that
/// it fired at a particular moment against a particular process, so the user can answer the
/// question a live grid can never answer: "what happened while I was away?"
/// </summary>
public sealed record SecurityEvent
{
    [JsonPropertyName("t")] public DateTime TimeUtc { get; init; } = DateTime.UtcNow;
    [JsonPropertyName("sev")] public Severity Severity { get; init; }
    [JsonPropertyName("score")] public int Score { get; init; }
    [JsonPropertyName("pid")] public int Pid { get; init; }
    [JsonPropertyName("proc")] public string Process { get; init; } = "";
    [JsonPropertyName("parent")] public string? Parent { get; init; }
    [JsonPropertyName("path")] public string? ImagePath { get; init; }
    [JsonPropertyName("cmd")] public string? CommandLine { get; init; }

    /// <summary>The headline rule — the strongest detection in the group.</summary>
    [JsonPropertyName("rule")] public string Rule { get; init; } = "";
    [JsonPropertyName("title")] public string Title { get; init; } = "";
    [JsonPropertyName("detail")] public string Detail { get; init; } = "";
    [JsonPropertyName("tech")] public string? Technique { get; init; }

    /// <summary>Every rule that fired for this process, so the detail pane can show the chain.</summary>
    [JsonPropertyName("all")] public IReadOnlyList<string> AllRules { get; init; } = [];

    [JsonIgnore] public DateTime TimeLocal => TimeUtc.ToLocalTime();

    /// <summary>Builds the event from a behaviour result, leading with its strongest finding.</summary>
    public static SecurityEvent From(BehaviorResult result)
    {
        var top = result.Detections.OrderByDescending(d => d.Score).First();
        var ctx = result.Context;
        return new SecurityEvent
        {
            Severity = result.Severity,
            Score = result.Score,
            Pid = ctx.Pid,
            Process = ctx.Name,
            Parent = ctx.ParentName,
            ImagePath = ctx.ImagePath,
            CommandLine = ctx.CommandLine,
            Rule = top.Rule,
            Title = top.Title,
            Detail = string.Join(" · ", result.Detections.Select(d => d.Detail)),
            Technique = top.Technique,
            AllRules = result.Detections.Select(d => d.Rule).ToList(),
        };
    }
}
