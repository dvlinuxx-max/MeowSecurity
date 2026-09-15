using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Sentinel.Core.Intel;

/// <summary>
/// Streams a file through SHA-256 (and, on demand, MD5) without ever holding the
/// whole thing in memory — a running process image can be hundreds of MB.
/// </summary>
public static class FileHasher
{
    /// <summary>SHA-256 of a file as a lowercase hex string, or null if it can't be read.</summary>
    public static async Task<string?> Sha256Async(string path, CancellationToken ct = default)
    {
        try
        {
            await using var fs = new FileStream(
                path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete,
                bufferSize: 1 << 20, useAsync: true);
            using var sha = SHA256.Create();
            var hash = await sha.ComputeHashAsync(fs, ct).ConfigureAwait(false);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }
        catch
        {
            // Locked, gone, or access denied — the caller treats a null hash as "can't verify".
            return null;
        }
    }

    /// <summary>SHA-256 as lowercase hex, synchronous — for callers already on a worker thread.</summary>
    public static string? Sha256(string path)
    {
        try
        {
            using var fs = new FileStream(
                path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete,
                bufferSize: 1 << 20, useAsync: false);
            using var sha = SHA256.Create();
            return Convert.ToHexString(sha.ComputeHash(fs)).ToLowerInvariant();
        }
        catch
        {
            return null;
        }
    }
}
