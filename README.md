# Sentinel (working name)

An advanced Windows process, memory, and network monitor / host intrusion detector.
User-mode, runs elevated (later a Windows service). Open source; a Microsoft Store
release is planned once it matures.

## Why user-mode
A full kernel driver on x64 needs a Microsoft-signed driver (EV cert + Hardware Dev
Center) and is blocked by PatchGuard for deep patching. Sentinel does as much as
possible from elevated user-mode — which covers hidden-process detection, injected-code
detection, and per-process network attribution — and leaves an optional kernel driver
for a distant phase.

## Layout
- `Sentinel.Core`  — engine library, no UI. Native interop under `Native/`.
- `Sentinel.Cli`   — command-line runner (for pros and for testing the engine).
- `Sentinel.Gui`   — WPF UI (later).

## Roadmap
1. Snapshot scanner: enumerate every process via multiple methods and diff them to
   surface hidden ones; per-process path, publisher, digital signature, origin.
2. Injection detection: walk each process's memory for executable-but-unbacked regions
   (shellcode), hollowing, reflective DLLs.
3. Network attribution: map every TCP/UDP endpoint to its owning process.
4. Live background service via ETW + alerts.
5. Reputation (VirusTotal / YARA), two-tier UI (simple verdict for users, deep detail
   for pros).
6. (Far, optional) kernel driver — gated on an EV cert.

## Build
Requires .NET 10 SDK (installed). From the repo root:
```
dotnet run --project Sentinel.Cli
```
Run an elevated terminal for full visibility into other processes.
