using System.Windows.Media;
using Sentinel.Core.Detect;

namespace Sentinel.Gui;

/// <summary>
/// One alert as the user meets it: what happened, what it means, and what to do.
///
/// The events page is a record — rules, technique ids, timestamps — and it is the right shape
/// for someone who already knows what those mean. This is the other half: the same finding
/// translated into two sentences and three buttons, because an alert nobody can act on only
/// teaches people to ignore the next one.
/// </summary>
public sealed class AlertCard
{
    public AlertCard(SecurityEvent ev)
    {
        Event = ev;
        var advice = Guidance.For(ev);
        Means = advice.Means;
        Do = advice.Do;
    }

    public SecurityEvent Event { get; }

    public string Title => Event.Title;
    public string Means { get; }
    public string Do { get; }
    public string When => Event.TimeLocal.ToString("HH:mm  ·  yyyy/MM/dd");

    /// <summary>The concrete process and file behind the alert.</summary>
    public string Where =>
        string.IsNullOrEmpty(Event.ImagePath)
            ? $"{Event.Process} (رقم {Event.Pid})"
            : $"{Event.Process} (رقم {Event.Pid})  —  {Event.ImagePath}";

    public string SeverityText => Event.Severity switch
    {
        Severity.Critical => "حرج",
        Severity.High => "مرتفع",
        Severity.Medium => "متوسط",
        _ => "منخفض",
    };

    public Brush Accent => Event.Severity switch
    {
        Severity.Critical => Res("Red"),
        Severity.High => Res("Red"),
        Severity.Medium => Res("Amber"),
        _ => Res("Line"),
    };

    public Brush Tint => Event.Severity switch
    {
        Severity.Critical or Severity.High => Res("RedTint"),
        Severity.Medium => Res("AmberTint"),
        _ => Res("Card"),
    };

    private static Brush Res(string key) => (Brush)App.Current.Resources[key];
}
