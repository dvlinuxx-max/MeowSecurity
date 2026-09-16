using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace MeowSecurity.Core.Ipc;

/// <summary>
/// The complete vocabulary the elevated helper understands.
///
/// It is an enumeration rather than a string for a reason that matters more than typing: an
/// elevated process reachable over a pipe is a privilege boundary, and the safest boundary is
/// one that cannot express dangerous requests at all. There is no "run this", no path to
/// execute, no registry key to write — only these four verbs, each with a fixed shape.
/// </summary>
public enum Command
{
    /// <summary>Liveness check, and how the client learns the helper is ready.</summary>
    Ping,

    /// <summary>Begin the kernel trace session and stream what it reports.</summary>
    StartCapture,

    /// <summary>Stop the session but stay running.</summary>
    StopCapture,

    /// <summary>Enable or disable one already-known autorun entry.</summary>
    SetAutorun,

    /// <summary>Exit. The helper also exits on its own when the client disconnects.</summary>
    Shutdown,
}

/// <summary>A request from the unprivileged application to the helper.</summary>
public sealed record Request
{
    [JsonPropertyName("cmd")] public Command Command { get; init; }

    /// <summary>SetAutorun: which entry, in the identity form the scanner produced.</summary>
    [JsonPropertyName("id")] public string? EntryId { get; init; }

    /// <summary>SetAutorun: the state being asked for.</summary>
    [JsonPropertyName("on")] public bool Enable { get; init; }
}

/// <summary>What the helper sends back: an answer, or an event it was asked to stream.</summary>
public sealed record Message
{
    [JsonPropertyName("type")] public string Type { get; init; } = "reply";

    [JsonPropertyName("ok")] public bool Ok { get; init; } = true;
    [JsonPropertyName("text")] public string? Text { get; init; }

    /// <summary>True when the failure is one the user can fix by granting rights.</summary>
    [JsonPropertyName("elevate")] public bool NeedsElevation { get; init; }

    // process-start events
    [JsonPropertyName("pid")] public int Pid { get; init; }
    [JsonPropertyName("ppid")] public int ParentPid { get; init; }
    [JsonPropertyName("name")] public string? Name { get; init; }
    [JsonPropertyName("parent")] public string? ParentName { get; init; }
    [JsonPropertyName("path")] public string? ImagePath { get; init; }
    [JsonPropertyName("cmd")] public string? CommandLine { get; init; }
    [JsonPropertyName("t")] public DateTime TimeUtc { get; init; }

    /// <summary>Per-process network totals since the last tick, as "pid:in:out" triples.</summary>
    [JsonPropertyName("net")] public string[]? Network { get; init; }

    public static Message Reply(bool ok, string? text = null, bool elevate = false) =>
        new() { Type = "reply", Ok = ok, Text = text, NeedsElevation = elevate };
}

/// <summary>
/// Length-prefixed JSON over the pipe.
///
/// A pipe is a byte stream, so a message needs its own boundary; four bytes of length in front
/// gives one, and it also caps how much a peer can make us allocate before we have agreed to
/// anything. Both halves of the boundary are validated: a frame larger than the cap is refused
/// rather than trusted.
/// </summary>
public static class Frame
{
    /// <summary>Generous for a command, far below anything worth worrying about.</summary>
    public const int MaxBytes = 64 * 1024;

    private static readonly JsonSerializerOptions Json = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static async Task WriteAsync<T>(Stream stream, T value, CancellationToken token = default)
    {
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(value, Json);
        if (payload.Length > MaxBytes) throw new InvalidOperationException("message too large");

        byte[] header = BitConverter.GetBytes(payload.Length);
        await stream.WriteAsync(header, token).ConfigureAwait(false);
        await stream.WriteAsync(payload, token).ConfigureAwait(false);
        await stream.FlushAsync(token).ConfigureAwait(false);
    }

    /// <summary>Returns null at end of stream, which is how a clean disconnect reads.</summary>
    public static async Task<T?> ReadAsync<T>(Stream stream, CancellationToken token = default)
    {
        byte[] header = new byte[4];
        if (!await FillAsync(stream, header, token).ConfigureAwait(false)) return default;

        int length = BitConverter.ToInt32(header);
        if (length <= 0 || length > MaxBytes) throw new InvalidDataException($"bad frame length {length}");

        byte[] payload = new byte[length];
        if (!await FillAsync(stream, payload, token).ConfigureAwait(false)) return default;

        return JsonSerializer.Deserialize<T>(payload, Json);
    }

    private static async Task<bool> FillAsync(Stream stream, byte[] buffer, CancellationToken token)
    {
        int read = 0;
        while (read < buffer.Length)
        {
            int n = await stream.ReadAsync(buffer.AsMemory(read), token).ConfigureAwait(false);
            if (n == 0) return false;
            read += n;
        }
        return true;
    }

    /// <summary>
    /// The pipe's name — one per user, so two accounts on a machine never collide.
    ///
    /// The user name is hashed rather than used directly, because a pipe name is visible to
    /// anything on the machine and there is no reason to publish who is logged in. It must be
    /// a stable hash: string.GetHashCode is randomised per process in .NET, so the two ends
    /// would derive different names and never meet.
    /// </summary>
    public static string PipeName
    {
        get
        {
            byte[] digest = System.Security.Cryptography.SHA256.HashData(
                Encoding.UTF8.GetBytes(Environment.UserName.ToLowerInvariant()));
            return "MeowSecurity.Engine." + Convert.ToHexString(digest, 0, 8);
        }
    }
}
