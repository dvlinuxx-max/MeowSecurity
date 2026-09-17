using System.Text.RegularExpressions;

namespace MeowSecurity.Core.Native;

/// <summary>A named pipe whose name matches a known command-and-control default.</summary>
/// <param name="Name">The pipe's name, as it appears on the machine.</param>
/// <param name="Framework">The tooling that pipe name belongs to.</param>
public readonly record struct SuspectPipe(string Name, string Framework);

/// <summary>
/// Reads the names of the machine's named pipes, and nothing else.
///
/// Post-exploitation frameworks talk to their own implants over named pipes, and they ship
/// with default names. Operators rename them, but a great many never do — and the ones that
/// do not are the cheapest true positive in this whole product: a string comparison against a
/// list, with no process to open and no memory to read.
///
/// **It never opens a pipe.** Asking a pipe who is serving it means connecting to it, and this
/// refuses to do that for two reasons. Connecting to an unknown implant's control channel is
/// an action with consequences we cannot predict, and connecting to an *innocent* pipe whose
/// server allows a single instance would take that instance and break a working program. A
/// monitor that damages the machine it is watching has failed at the only job it had, so this
/// reads the directory and stops there — which costs the owning process's identity, and is
/// worth it.
/// </summary>
public static class NamedPipes
{
    /// <summary>
    /// Default pipe names from published post-exploitation tooling.
    ///
    /// Every pattern here is anchored and includes the variable part these tools append, so
    /// that it cannot match the legitimate Windows pipe it was modelled on: Windows serves
    /// <c>wkssvc</c> and <c>ntsvcs</c> exactly, while the imitations carry a suffix. Matching
    /// the bare names would flag a healthy machine on every scan.
    ///
    /// The list is short on purpose, and two patterns were removed from it after being checked
    /// against a real desktop's 136 pipes. Chrome and Edge name theirs
    /// <c>LOCAL\mojo.16912.16492.10928790902490904378</c>, and a pattern written from memory
    /// for a framework that supposedly imitates them matched that shape almost exactly. A rule
    /// that fires on every browser tab is worse than no rule, and a pattern nobody can point to
    /// a source for is not evidence — so only defaults that are actually documented are here.
    /// </summary>
    private static readonly (Regex Pattern, string Framework)[] Known =
    {
        (new Regex(@"^msagent_[0-9a-f]{1,4}$", RegexOptions.IgnoreCase), "Cobalt Strike"),
        (new Regex(@"^postex_[0-9a-f]{4}$", RegexOptions.IgnoreCase), "Cobalt Strike"),
        (new Regex(@"^postex_ssh_[0-9a-f]{4}$", RegexOptions.IgnoreCase), "Cobalt Strike"),
        (new Regex(@"^status_[0-9a-f]{1,4}$", RegexOptions.IgnoreCase), "Cobalt Strike"),
        (new Regex(@"^MSSE-[0-9a-f]{3,4}-server$", RegexOptions.IgnoreCase), "Cobalt Strike"),
        (new Regex(@"^netsvc_[0-9a-f]{1,4}$", RegexOptions.IgnoreCase), "Cobalt Strike"),
        (new Regex(@"^windows\.update\.manager\w*$", RegexOptions.IgnoreCase), "Cobalt Strike"),
        (new Regex(@"^ntsvcs[0-9a-f]+$", RegexOptions.IgnoreCase), "Cobalt Strike (named after ntsvcs)"),
        (new Regex(@"^scerpc[0-9a-f]+$", RegexOptions.IgnoreCase), "Cobalt Strike (named after scerpc)"),
        (new Regex(@"^wkssvc[0-9a-f]+$", RegexOptions.IgnoreCase), "Cobalt Strike (named after wkssvc)"),
        (new Regex(@"^gruntsvc", RegexOptions.IgnoreCase), "Covenant"),
    };

    /// <summary>
    /// Pipes whose names match known tooling. Empty is the expected answer, on every machine
    /// that is not currently hosting somebody else's software.
    /// </summary>
    public static IReadOnlyList<SuspectPipe> FindSuspect()
    {
        var found = new List<SuspectPipe>();

        foreach (string name in All())
        {
            // Pipes may sit under a prefix — Chrome's live under "LOCAL\" — so the patterns,
            // which describe a pipe's own name, are tried against the leaf as well.
            int slash = name.LastIndexOf('\\');
            string leaf = slash >= 0 ? name[(slash + 1)..] : name;

            foreach (var (pattern, framework) in Known)
                if (pattern.IsMatch(name) || pattern.IsMatch(leaf))
                {
                    found.Add(new SuspectPipe(name, framework));
                    break;
                }
        }

        return found;
    }

    /// <summary>
    /// Every named pipe on the machine, by name.
    ///
    /// The pipe filesystem holds names that are not legal Win32 paths, and enumerating it can
    /// throw for a single bad entry. Each name is therefore taken on its own and a failure
    /// costs that one name rather than the whole listing.
    /// </summary>
    public static IReadOnlyList<string> All()
    {
        var names = new List<string>();
        try
        {
            foreach (string entry in Directory.EnumerateFileSystemEntries(@"\\.\pipe\"))
            {
                try
                {
                    string name = entry.StartsWith(@"\\.\pipe\", StringComparison.Ordinal)
                        ? entry[@"\\.\pipe\".Length..]
                        : Path.GetFileName(entry);
                    if (name.Length > 0) names.Add(name);
                }
                catch { /* one unnameable pipe must not cost the rest of the list */ }
            }
        }
        catch { /* the pipe filesystem is unavailable; nothing to report */ }
        return names;
    }
}
