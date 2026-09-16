using System.Windows.Media;
using MeowSecurity.Core.Persistence;
using MeowSecurity.Core.Processes;

using MeowSecurity.Core.Localization;

namespace MeowSecurity.Gui;

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

    /// <summary>The entry behind the row, so the page can act on it.</summary>
    public AutorunEntry Entry { get; } = e;

    public bool Enabled => Entry.Enabled;
    public string EnabledText => Entry.Enabled ? Strings.T("common.yes") : Strings.T("common.disabled");
    public Brush EnabledAccent => Entry.Enabled ? Res("Muted") : Res("Faint");

    /// <summary>
    /// A validly signed Windows component. There are hundreds of these — every driver and
    /// scheduled task the OS ships with — and none of them is what anyone opened this page to
    /// find, so by default they are folded away and the count is shown instead.
    /// </summary>
    public bool IsSystem { get; } =
        e.Signature == SignatureState.SignedValid &&
        ((e.Publisher?.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) ?? false) ||
         (e.ImagePath?.StartsWith(
             Environment.GetFolderPath(Environment.SpecialFolder.Windows),
             StringComparison.OrdinalIgnoreCase) ?? false));

    public string VerdictText => Verdict switch
    {
        Verdict.Suspicious => Strings.T("verdict.suspicious"),
        Verdict.Review => Strings.T("verdict.review"),
        _ => Strings.T("verdict.safe"),
    };

    public string SignatureText => Entry.Signature switch
    {
        SignatureState.SignedValid => Strings.T("signature.signed"),
        SignatureState.SignedInvalid => Strings.T("signature.invalid"),
        SignatureState.Unsigned => Strings.T("signature.unsigned"),
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
