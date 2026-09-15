using System.Windows.Media;
using Sentinel.Core.Persistence;
using Sentinel.Core.Processes;

namespace Sentinel.Gui;

/// <summary>An autorun entry shaped for the grid, with a verdict badge like the process rows.</summary>
public sealed class AutorunRow(AutorunEntry e)
{
    public string Name { get; } = e.Name;
    public string Location { get; } = e.Location;
    public string Path { get; } = e.ImagePath ?? e.Command;
    public string Publisher { get; } = e.Publisher ?? "";
    public string Reason { get; } = e.Reason;
    public Verdict Verdict { get; } = e.Verdict;
    public bool IsFlagged => Verdict != Verdict.Safe;

    public string VerdictText => Verdict switch
    {
        Verdict.Suspicious => "مشبوه",
        Verdict.Review => "راجعه",
        _ => "آمن",
    };

    public string SignatureText => e.Signature switch
    {
        SignatureState.SignedValid => "موقّع",
        SignatureState.SignedInvalid => "غير صالح",
        SignatureState.Unsigned => "غير موقّع",
        _ => "—",
    };

    public Brush Accent => Verdict switch
    {
        Verdict.Suspicious => Res("Red"),
        Verdict.Review => Res("Amber"),
        _ => Res("Green"),
    };

    public Brush Tint => Verdict switch
    {
        Verdict.Suspicious => Res("RedTint"),
        Verdict.Review => Res("AmberTint"),
        _ => Res("GreenTint"),
    };

    private static Brush Res(string key) => (Brush)App.Current.Resources[key];
}
