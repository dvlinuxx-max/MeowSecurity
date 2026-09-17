using System.Runtime.InteropServices;
using System.Text;
using MeowSecurity.Core.Processes;

namespace MeowSecurity.Core.Native;

/// <summary>A library loaded into a process from somewhere the process had no business loading it.</summary>
/// <param name="FilePath">Where the library actually lives.</param>
/// <param name="Signature">What its signature turned out to be.</param>
public readonly record struct ForeignModule(string FilePath, SignatureState Signature);

/// <summary>
/// Reads what each process has loaded, looking for the shape of a hijacked library.
///
/// Side-loading is the quietest way to run code inside a program somebody trusts. Nothing is
/// injected and nothing is patched: a DLL with the right name is simply placed where the
/// program looks first, and Windows loads it because that is what Windows is supposed to do.
/// The process stays signed, the parent chain stays innocent, and every rule that judges a
/// process by its own image says it is fine — because it is. The lie is one directory down.
///
/// So the question here is not "is this DLL signed" but "does a signed program have an
/// unsigned library loaded from a folder any malware could write to". Windows' own libraries
/// live in Windows' own folders; a trusted program reaching outside them for code is the
/// finding, and it is also rare enough to be worth saying out loud.
/// </summary>
public static class ModuleInspector
{
    private static readonly string WinDir =
        Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLowerInvariant();
    private static readonly string ProgramFiles =
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles).ToLowerInvariant();
    private static readonly string ProgramFilesX86 =
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86).ToLowerInvariant();

    /// <summary>Folders any user — or anything running as them — can drop a file into.</summary>
    private static readonly string[] UserWritable =
    {
        @"\appdata\local\temp\", @"\appdata\roaming\", @"\appdata\local\",
        @"\windows\temp\", @"\downloads\", @"\programdata\", @"\public\", @"\$recycle.bin\",
    };

    /// <summary>
    /// Libraries loaded into <paramref name="pid"/> from a user-writable folder that are not
    /// validly signed.
    ///
    /// Only modules outside the system folders are verified at all. A signature check costs
    /// real time and there are a couple of thousand distinct system DLLs on a running machine;
    /// checking them would buy nothing, because a DLL in System32 loaded by a signed program
    /// is the definition of ordinary. Filtering on location first turns a minutes-long sweep
    /// into one that finds nothing at all on a clean machine, quickly.
    /// </summary>
    public static IReadOnlyList<ForeignModule> FindUntrustedModules(int pid)
    {
        var found = new List<ForeignModule>();
        if (pid <= 4 || pid == Environment.ProcessId) return found;

        IntPtr process = MemoryApi.OpenProcess(
            MemoryApi.ProcessAccess.QueryInformation | MemoryApi.ProcessAccess.VmRead, false, pid);
        if (process == IntPtr.Zero) return found;   // protected, or not ours to read

        try
        {
            if (!MemoryApi.EnumProcessModulesEx(process, null, 0, out uint needed,
                    MemoryApi.LIST_MODULES_ALL) && needed == 0)
                return found;

            var handles = new IntPtr[needed / IntPtr.Size];
            if (!MemoryApi.EnumProcessModulesEx(process, handles, needed, out _,
                    MemoryApi.LIST_MODULES_ALL))
                return found;

            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var name = new StringBuilder(1024);

            foreach (IntPtr module in handles)
            {
                name.Clear();
                if (GetModuleFileNameEx(process, module, name, name.Capacity) == 0) continue;

                string path = name.ToString();
                if (path.Length == 0 || !seen.Add(path)) continue;

                string lower = path.ToLowerInvariant();
                if (IsSystemLocation(lower)) continue;
                if (!UserWritable.Any(lower.Contains)) continue;

                var (state, _) = SignatureCache.Get(path);
                if (state is SignatureState.Unsigned or SignatureState.SignedInvalid)
                    found.Add(new ForeignModule(path, state));
            }
        }
        catch { /* the process died mid-walk; report what we have */ }
        finally { MemoryApi.CloseHandle(process); }

        return found;
    }

    private static bool IsSystemLocation(string lowerPath) =>
        lowerPath.StartsWith(WinDir, StringComparison.Ordinal) ||
        lowerPath.StartsWith(ProgramFiles, StringComparison.Ordinal) ||
        (ProgramFilesX86.Length > 0 && lowerPath.StartsWith(ProgramFilesX86, StringComparison.Ordinal));

    [DllImport("psapi.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "GetModuleFileNameExW")]
    private static extern uint GetModuleFileNameEx(
        IntPtr process, IntPtr module, StringBuilder name, int size);
}
