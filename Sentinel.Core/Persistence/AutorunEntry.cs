using Sentinel.Core.Processes;

namespace Sentinel.Core.Persistence;

/// <summary>One thing Windows launches automatically — a registry Run value, a Startup-folder
/// shortcut, an auto-start service. Persistence is where malware hides to survive a reboot, so
/// each entry is signature-checked and scored the same way a running process is.</summary>
public sealed class AutorunEntry
{
    public required string Name { get; init; }
    public required string Location { get; init; }   // e.g. "HKCU\Run", "مجلد بدء التشغيل"
    public required string Command { get; init; }    // raw command line as registered
    public string? ImagePath { get; init; }          // resolved executable
    public string? Publisher { get; set; }
    public SignatureState Signature { get; set; }
    public Verdict Verdict { get; set; }
    public string Reason { get; set; } = "";
}
