using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Media;

namespace Sentinel.Gui;

/// <summary>
/// Dark/light theming for a StaticResource-based app.
///
/// WPF freezes resource brushes when the XAML uses them, so they can't be recoloured
/// in place. Instead we replace each palette brush in App.Resources with a fresh brush
/// of the chosen theme *before* a window is built — every StaticResource then binds to
/// the themed colour. Switching theme re-applies the palette and re-creates the window.
/// </summary>
public static class ThemeManager
{
    public static string Current { get; private set; } = "dark";

    // key -> (dark, light). One row per SolidColorBrush resource.
    private static readonly Dictionary<string, (string dark, string light)> Solids = new()
    {
        ["Bg"]          = ("#131009", "#F1ECE1"),
        ["Panel"]       = ("#1A160F", "#ECE5D7"),
        ["Card"]        = ("#211C13", "#FBF8F1"),
        ["CardAlt"]     = ("#1B1710", "#F3EDE1"),
        ["Line"]        = ("#342C1E", "#E2D8C6"),
        ["Text"]        = ("#F6EEDF", "#241C10"),
        ["Muted"]       = ("#B7A98F", "#6E6250"),
        ["Faint"]       = ("#7C6F58", "#9E9078"),
        ["Brand"]       = ("#FF6A16", "#EA5E08"),
        ["BrandGlow"]   = ("#FF9838", "#FF9838"),
        ["BrandDeep"]   = ("#3E2610", "#FBE6D2"),
        ["Green"]       = ("#34D399", "#0FA968"),
        ["GreenTint"]   = ("#123024", "#DCF5E9"),
        ["Amber"]       = ("#FFB020", "#C4820A"),
        ["AmberTint"]   = ("#3A2C0C", "#FAEEC9"),
        ["Red"]         = ("#FF4D5E", "#E23144"),
        ["RedTint"]     = ("#3A1518", "#FBE0E3"),
        ["ServiceText"] = ("#C9A2FF", "#7A3FD6"),
        ["NewTint"]     = ("#13301F", "#E4F5EA"),
        ["NetIn"]       = ("#38BDF8", "#0C8FCC"),
        ["NetOut"]      = ("#34D399", "#0FA968"),
        ["CpuFill"]     = ("#33FF6A16", "#22FF6A16"),
        ["MemFill"]     = ("#33FFB020", "#22C4820A"),
        ["NetFill"]     = ("#2438BDF8", "#1A0C8FCC"),
    };

    private sealed record GradSpec(Point Start, Point End, double[] Offsets, string[] Dark, string[] Light);

    private static readonly Dictionary<string, GradSpec> Gradients = new()
    {
        ["BgGrad"]   = new(new Point(0, 0), new Point(0, 1), new[] { 0.0, 1.0 },
                           new[] { "#181309", "#100D07" }, new[] { "#F5F0E6", "#EBE4D6" }),
        ["CardGrad"] = new(new Point(0, 0), new Point(0, 1), new[] { 0.0, 1.0 },
                           new[] { "#241E14", "#1B1710" }, new[] { "#FFFFFF", "#F5EFE3" }),
        ["HeroWash"] = new(new Point(1, 0), new Point(0, 1), new[] { 0.0, 0.6, 1.0 },
                           new[] { "#2A1B0C", "#1C1710", "#1C1710" }, new[] { "#FDEFDD", "#FBF8F1", "#FBF8F1" }),
        ["BrandGrad"] = new(new Point(0, 0), new Point(1, 1), new[] { 0.0, 0.55, 1.0 },
                           new[] { "#FFAE44", "#FF6A16", "#FF4A00" }, new[] { "#FFAE44", "#FF6A16", "#FF4A00" }),
    };

    /// <summary>Replace every palette brush in App.Resources with a fresh brush for the theme.</summary>
    public static void Apply(string theme)
    {
        bool light = string.Equals(theme, "light", StringComparison.OrdinalIgnoreCase);
        Current = light ? "light" : "dark";
        var res = Application.Current.Resources;

        foreach (var (key, pair) in Solids)
            res[key] = new SolidColorBrush(Parse(light ? pair.light : pair.dark));

        foreach (var (key, spec) in Gradients)
        {
            var stops = new GradientStopCollection();
            var colors = light ? spec.Light : spec.Dark;
            for (int i = 0; i < spec.Offsets.Length; i++)
                stops.Add(new GradientStop(Parse(colors[i]), spec.Offsets[i]));
            res[key] = new LinearGradientBrush(stops) { StartPoint = spec.Start, EndPoint = spec.End };
        }
    }

    private static Color Parse(string hex) => (Color)ColorConverter.ConvertFromString(hex)!;
}
