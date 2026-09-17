using System.Management;

namespace MeowSecurity.Core.Persistence;

/// <summary>One WMI event subscription: a trigger, and the thing it runs.</summary>
/// <param name="Name">The binding's consumer name, which is what identifies it.</param>
/// <param name="Query">The WQL query that decides when it fires.</param>
/// <param name="Action">The command or script it runs when it does.</param>
/// <param name="ConsumerClass">Which kind of consumer — a command line, or a script engine.</param>
public readonly record struct WmiSubscription(
    string Name, string Query, string Action, string ConsumerClass);

/// <summary>
/// The persistence that survives everything else.
///
/// A WMI event subscription is three objects in a database rather than a file or a registry
/// value: a filter holding a query, a consumer holding a command, and a binding tying them
/// together. Nothing appears in any Run key, nothing sits in a Startup folder, and nothing
/// shows up in Task Scheduler — so a person who has carefully checked all three has checked
/// nothing that would find it. It runs whenever its query matches, which for an attacker
/// usually means a few seconds after every boot, forever.
///
/// Very little legitimate software registers one that *runs* something, which makes it that
/// rare thing in detection: a place where merely being there is most of the finding. Only the
/// consumers that execute are reported — Windows itself ships a logging subscription on every
/// machine, and a scan that could not tell the two apart would warn about Windows.
///
/// This reports and does not remove. Deleting one means writing to the WMI repository as an
/// administrator, and the elevated helper accepts exactly the five verbs it was justified
/// with — a sixth would need its own justification, and "report it clearly" is worth more
/// here than "delete it quietly" anyway.
/// </summary>
public static class WmiPersistence
{
    /// <summary>
    /// Every filter-to-consumer binding registered on this machine.
    ///
    /// Reading <c>root\subscription</c> normally needs administrator rights. Without them this
    /// returns nothing and says so through <paramref name="readable"/>, because an empty list
    /// and a list we were not allowed to read mean opposite things and must not look alike.
    /// </summary>
    public static IReadOnlyList<WmiSubscription> Scan(out bool readable)
    {
        readable = false;
        var found = new List<WmiSubscription>();

        try
        {
            var scope = new ManagementScope(@"\\.\root\subscription");
            scope.Connect();
            if (!scope.IsConnected) return found;
            readable = true;

            // The filters and consumers are looked up by name from the bindings, rather than
            // listed separately, because an unbound filter does nothing and an unbound consumer
            // never fires. Only the pairing is persistence.
            var filters = ByName(scope, "__EventFilter", "Query");
            var commands = ByName(scope, "CommandLineEventConsumer", "CommandLineTemplate");
            var scripts = ByName(scope, "ActiveScriptEventConsumer", "ScriptText");

            using var bindings = new ManagementObjectSearcher(
                scope, new ObjectQuery("SELECT * FROM __FilterToConsumerBinding"));

            foreach (ManagementObject binding in bindings.Get())
            {
                using (binding)
                {
                    string filterName = RefName(binding["Filter"]?.ToString());
                    string consumerName = RefName(binding["Consumer"]?.ToString());

                    // Only two kinds of consumer execute anything. The others — the event-log
                    // and log-file consumers — write a line somewhere and stop, which is not
                    // persistence and cannot be made into it.
                    //
                    // This is not a detail. Windows ships its own subscription on every machine
                    // (`SCM Event Log Consumer`, bound to the service control manager), so a
                    // rule that reported every binding would put a permanent warning about a
                    // Windows component in front of every user who ever opened the page. Asking
                    // what the consumer can actually *do* removes that without an allow-list an
                    // attacker could simply name themselves into.
                    string consumerClass, action;
                    if (commands.TryGetValue(consumerName, out string? c))
                        (consumerClass, action) = ("CommandLineEventConsumer", c);
                    else if (scripts.TryGetValue(consumerName, out string? s))
                        (consumerClass, action) = ("ActiveScriptEventConsumer", s);
                    else
                        continue;

                    found.Add(new WmiSubscription(
                        consumerName,
                        filters.TryGetValue(filterName, out string? q) ? q : "",
                        Flatten(action),
                        consumerClass));
                }
            }
        }
        catch { /* no rights, or WMI is unwell — either way, nothing to report */ }

        return found;
    }

    private static Dictionary<string, string> ByName(
        ManagementScope scope, string className, string property)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var search = new ManagementObjectSearcher(
                scope, new ObjectQuery($"SELECT Name, {property} FROM {className}"));

            foreach (ManagementObject o in search.Get())
                using (o)
                {
                    string? name = o["Name"]?.ToString();
                    if (!string.IsNullOrEmpty(name))
                        map[name] = o[property]?.ToString() ?? "";
                }
        }
        catch { /* the class may not exist on this machine, which is normal */ }
        return map;
    }

    /// <summary>
    /// A binding refers to its halves by object path — <c>__EventFilter.Name="X"</c> — so the
    /// name has to be pulled back out of the reference.
    /// </summary>
    private static string RefName(string? reference)
    {
        if (string.IsNullOrEmpty(reference)) return "";
        int quote = reference.IndexOf('"');
        if (quote < 0) return reference;
        int close = reference.IndexOf('"', quote + 1);
        return close < 0 ? reference : reference[(quote + 1)..close];
    }

    /// <summary>A script can be hundreds of lines; the alert needs the first of them.</summary>
    private static string Flatten(string text)
    {
        var flat = text.ReplaceLineEndings(" ").Trim();
        while (flat.Contains("  ")) flat = flat.Replace("  ", " ");
        return flat.Length <= 200 ? flat : flat[..200] + "…";
    }
}
