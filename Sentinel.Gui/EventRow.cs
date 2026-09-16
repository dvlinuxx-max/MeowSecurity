using System.Windows.Media;
using Sentinel.Core.Detect;

namespace Sentinel.Gui;

/// <summary>A recorded security event shaped for the timeline grid, with a severity badge.</summary>
public sealed class EventRow(SecurityEvent e)
{
    public SecurityEvent Event { get; } = e;

    public string Time { get; } = e.TimeLocal.ToString("HH:mm:ss");
    public string Date { get; } = e.TimeLocal.ToString("yyyy/MM/dd");
    public string Process { get; } = $"{e.Process} ({e.Pid})";
    public string Parent { get; } = e.Parent ?? "—";
    public string Title { get; } = e.Title;
    public string Detail { get; } = e.Detail;
    public string Technique { get; } = e.Technique ?? "—";
    public int Score { get; } = e.Score;
    public Severity Severity { get; } = e.Severity;

    /// <summary>Everything about this event, for the row tooltip — path, command line, rules.</summary>
    public string Tip
    {
        get
        {
            var lines = new List<string> { $"{Date} {Time}  ·  نقاط الخطورة {Score}" };
            if (!string.IsNullOrEmpty(Event.ImagePath)) lines.Add(Event.ImagePath);
            if (!string.IsNullOrEmpty(Event.CommandLine)) lines.Add(Event.CommandLine);
            lines.Add(Event.Detail);
            if (Event.AllRules.Count > 0) lines.Add(string.Join("  ", Event.AllRules));
            return string.Join("\n", lines);
        }
    }

    public string SeverityText => Severity switch
    {
        Severity.Critical => "حرج",
        Severity.High => "عالٍ",
        Severity.Medium => "متوسط",
        Severity.Low => "منخفض",
        _ => "معلومة",
    };

    public Brush Accent => Severity switch
    {
        Severity.Critical or Severity.High => Res("Red"),
        Severity.Medium => Res("Amber"),
        _ => Res("Muted"),
    };

    public Brush Tint => Severity switch
    {
        Severity.Critical or Severity.High => Res("RedTint"),
        Severity.Medium => Res("AmberTint"),
        _ => Res("Card"),
    };

    private static Brush Res(string key) => (Brush)App.Current.Resources[key];
}
