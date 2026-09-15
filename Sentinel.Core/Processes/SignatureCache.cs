using System.Collections.Concurrent;

namespace Sentinel.Core.Processes;

/// <summary>
/// WinVerifyTrust is expensive, and the same image path (svchost.exe, RuntimeBroker.exe)
/// shows up dozens of times in one scan. Cache the verdict per path+size+mtime so we pay
/// it once. Thread-safe so the scan can run in parallel.
/// </summary>
internal static class SignatureCache
{
    private readonly record struct Key(string Path, long Size, long Ticks);

    private static readonly ConcurrentDictionary<Key, (SignatureState, string?)> Map = new();

    public static (SignatureState state, string? publisher) Get(string imagePath)
    {
        try
        {
            var fi = new FileInfo(imagePath);
            var key = new Key(imagePath.ToLowerInvariant(), fi.Length, fi.LastWriteTimeUtc.Ticks);
            return Map.GetOrAdd(key, _ => Signing.Check(imagePath));
        }
        catch
        {
            return Signing.Check(imagePath);
        }
    }

    public static void Clear() => Map.Clear();
}
