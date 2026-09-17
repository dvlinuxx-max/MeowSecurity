<div align="center">

<img src="MeowSecurity.Gui/meow-security.png" width="140" alt="Meow Security">

# Meow Security

**A Windows process, memory and network monitor — and a host intrusion detector.**
Runs entirely offline. Sends nothing, anywhere.

[![Licence: GPL v3](https://img.shields.io/badge/licence-GPL--3.0-orange.svg)](LICENSE)
![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-blue)
![.NET](https://img.shields.io/badge/.NET-10-512BD4)

</div>

---

## What it does

Most monitors tell you *what* is running. This one is built around *why* — because
modern intrusions rarely drop a novel binary. They drive trusted, signed Windows
tools, and a clean hash proves very little. What gives them away is context: who
launched a process, from where, and with what arguments.

- **Behavioural detection.** Rules score each process on its parent chain, command
  line, image location and masquerading, and tag findings with MITRE ATT&CK ids.
  An encoded PowerShell command is decoded and judged by what it actually contains
  — hiding an attack scores worse than running one in the open; hiding an ordinary
  command is merely logged.
- **Live capture from the kernel.** Processes are judged the moment they are
  created, so a one-liner that runs and exits in 300 ms is not missed the way any
  one-second poll would miss it.
- **Per-process network throughput.** Windows keeps no such counter — even Task
  Manager's network column is machine-wide. This one adds up the kernel's own
  send and receive events, so you can see which program is uploading.
- **Credential-theft detection.** Every cross-process handle on the machine is
  resolved to the process it names. A handle to LSASS with read access is how
  credentials are stolen, whatever the tool is called and whoever signed it — the
  handle is the act, not a clue about it.
- **Hidden process detection.** Every process is enumerated through two
  independent sources and the lists are diffed; anything visible to one and not
  the other is surfaced.
- **Injected code detection.** Executable memory with no file behind it, PE
  headers implanted in another process's address space, and threads whose entry
  point lies outside every mapped image — code running from nowhere on disk.
- **Autoruns, with control.** Registry Run keys, Startup folders, auto-starting
  services and drivers, and scheduled tasks — signature-checked, and each one can
  be opened, disabled or removed. Disabling writes the same flags Task Manager
  uses, so the machine agrees with itself and every change can be undone.
- **A durable event log,** so "what happened while I was away" has an answer.
- **Plain-language alerts.** Every finding comes with what it means and what to do
  about it, in two sentences, with the buttons to do it.

## Screens

Overview · Processes · Network · Autoruns · Threats · Alerts · Events · Settings.
Arabic interface, light and dark themes.

## Privacy

It collects nothing and transmits nothing. There are no accounts, no keys, no
telemetry and no servers. See [PRIVACY.md](PRIVACY.md) for exactly what is written
to disk and where.

## Building

Requires the .NET 10 SDK on Windows.

```
dotnet build MeowSecurity.Gui/MeowSecurity.Gui.csproj
dotnet run   --project MeowSecurity.Cli -- --rule-test
```

Run elevated for full visibility: the live kernel capture, protected processes and
machine-wide autoruns all need administrator rights. Without them the monitor
still runs and tells you which parts are limited.

### Command line

| Flag | Does |
|---|---|
| `--rule-test` | Detection regression suite — attack shapes that must fire, developer noise that must stay silent. |
| `--watch [seconds]` | Live process starts and per-process network, from the kernel. |
| `--handles` | Every cross-process handle, resolved, with the parent/child ones marked. |
| `--threads` | Threads starting outside any mapped image. Prints nothing on a clean machine. |
| `--events [--all]` | The recorded security events. |
| `--autoruns` | Everything that starts by itself, with its verdict. |
| `--autorun-on/off <name>` | Enable or disable one startup entry. |
| `--startup-on/off` | Register or remove "start with Windows". |

## Not an antivirus

Meow Security is a monitor and an analyser. It is not a replacement for Microsoft
Defender or any antivirus, and it does not try to be one.

## Licence

[GNU General Public License v3.0](LICENSE). You may use, study and modify this
freely; any copy you distribute must remain open source under the same licence.

Copyright © 2026 Mohammed Abd Alrahman
[mohmadev.com](https://mohmadev.com) · [github.com/dvlinuxx-max](https://github.com/dvlinuxx-max)
