using System.Runtime.InteropServices;
using System.Text;

namespace MeowSecurity.Core.Etw;

/// <summary>
/// Translates kernel paths into ones a human — and File.Exists — can use.
///
/// ETW reports images the way the kernel sees them, as "\Device\HarddiskVolume3\Windows\
/// System32\cmd.exe". Nothing in the managed world accepts that, and showing it to the user
/// would be gibberish, so each drive letter is asked once which device it maps to and the
/// answers are cached. The map is built lazily and refreshed if a lookup misses, because
/// drives appear and disappear while the monitor is running.
/// </summary>
internal static class NtPath
{
    private static readonly object Lock = new();
    private static Dictionary<string, string>? _deviceToDrive;

    public static string? ToDosPath(string ntPath)
    {
        if (string.IsNullOrEmpty(ntPath)) return null;
        if (!ntPath.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
            return ntPath;   // already a normal path, or something we should not rewrite

        var map = GetMap(refresh: false);
        string? dos = Translate(ntPath, map);
        if (dos is not null) return dos;

        // A drive we have not seen before — rebuild once before giving up.
        return Translate(ntPath, GetMap(refresh: true)) ?? ntPath;
    }

    private static string? Translate(string ntPath, Dictionary<string, string> map)
    {
        foreach (var (device, drive) in map)
        {
            if (ntPath.StartsWith(device, StringComparison.OrdinalIgnoreCase) &&
                ntPath.Length > device.Length && ntPath[device.Length] == '\\')
                return drive + ntPath[device.Length..];
        }
        return null;
    }

    private static Dictionary<string, string> GetMap(bool refresh)
    {
        lock (Lock)
        {
            if (_deviceToDrive is not null && !refresh) return _deviceToDrive;

            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var buffer = new StringBuilder(260);
            for (char letter = 'A'; letter <= 'Z'; letter++)
            {
                string drive = $"{letter}:";
                buffer.Clear();
                if (QueryDosDevice(drive, buffer, buffer.Capacity) != 0)
                    map[buffer.ToString()] = drive;
            }
            return _deviceToDrive = map;
        }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int QueryDosDevice(string deviceName, StringBuilder target, int max);
}
