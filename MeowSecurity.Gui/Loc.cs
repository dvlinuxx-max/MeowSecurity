using System.Windows.Markup;
using MeowSecurity.Core.Localization;

namespace MeowSecurity.Gui;

/// <summary>
/// Lets XAML read from the same string table the engine uses: <c>Text="{loc:T page.events}"</c>.
///
/// The value is resolved once, when the window is built. That is deliberate rather than a
/// limitation — switching language rebuilds the window anyway, for the same reason switching
/// theme does: WPF freezes much of what a window binds at load, and a fresh window is both
/// simpler and more reliable than trying to re-flow a live one.
/// </summary>
[MarkupExtensionReturnType(typeof(string))]
public sealed class TExtension : MarkupExtension
{
    public TExtension() { }

    public TExtension(string key) => Key = key;

    [ConstructorArgument("key")]
    public string Key { get; set; } = "";

    public override object ProvideValue(IServiceProvider serviceProvider) => Strings.T(Key);
}
