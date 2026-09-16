# Meow Security

An advanced Windows process, memory, and network monitor / host intrusion detector.
User-mode, runs elevated (later a Windows service). Free software; a Microsoft Store
release is planned once it matures.

Codebase namespaces still read `Sentinel.*` — that was the working name.

## Why user-mode
A full kernel driver on x64 needs a Microsoft-signed driver (EV cert + Hardware Dev
Center) and is blocked by PatchGuard for deep patching. Meow Security does as much as
possible from elevated user-mode — which covers hidden-process detection, injected-code
detection, and per-process network attribution — and leaves an optional kernel driver
for a distant phase.

## Layout
- `MeowSecurity.Core`  — engine library, no UI. Native interop under `Native/`.
- `MeowSecurity.Cli`   — command-line runner (for pros and for testing the engine).
- `MeowSecurity.Gui`   — WPF UI (later).

## Roadmap
1. Snapshot scanner: enumerate every process via multiple methods and diff them to
   surface hidden ones; per-process path, publisher, digital signature, origin.
2. Injection detection: walk each process's memory for executable-but-unbacked regions
   (shellcode), hollowing, reflective DLLs.
3. Network attribution: map every TCP/UDP endpoint to its owning process.
4. Behavioural detection: judge a process by its parent, its command line and where it runs
   from, not just its hash — then record every finding to a durable event log. *(done; the
   rules are regression-tested with `sentinel --rule-test`)*
5. Reputation (VirusTotal / YARA), two-tier UI (simple verdict for users, deep detail
   for pros).
6. Live background service via ETW + alerts.
7. (Far, optional) kernel driver — gated on an EV cert.

## Build
Requires .NET 10 SDK (installed). From the repo root:
```
dotnet run --project MeowSecurity.Cli
```
Run an elevated terminal for full visibility into other processes.

Useful flags: `--rule-test` (detection regression suite), `--events` (the security
event log), `--autoruns` (everything that starts by itself), `--scan <file|url|ip>`.

## Licence
GNU General Public License v3.0 — see [LICENSE](LICENSE). You may use, study and
modify this freely; any copy you distribute must stay open source under the same
licence.

Copyright (c) 2026 Mohammed Abd Alrahman
· [mohmadev.com](https://mohmadev.com)
· [github.com/dvlinuxx-max](https://github.com/dvlinuxx-max)

## Not an antivirus
Meow Security is a monitor and analyser. It is not a replacement for Microsoft
Defender or any antivirus, and it makes no attempt to be one.
