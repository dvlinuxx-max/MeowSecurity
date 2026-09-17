# Restricted capability justification — `allowElevation`

**Product:** Meow Security · **Store ID:** `9MXL3CXWWLPJ`
**Publisher:** Mohammed Abd Alrahman
**Website:** [mohmadev.com](https://mohmadev.com) · **Support:** [GitHub Issues](https://github.com/dvlinuxx-max/MeowSecurity/issues)
**Source:** the whole product is published under GPL-3.0 at
[github.com/dvlinuxx-max/MeowSecurity](https://github.com/dvlinuxx-max/MeowSecurity) —
every claim below can be read in the code rather than taken on trust.

This document answers the five questions the Store Certification team asks of a
restricted capability. It is written to be checked, so each answer names the file that
implements it.

---

## 1. Why the product requires this capability

Meow Security is a host intrusion detector. Its purpose is to notice an intrusion that
carries no novel binary — an attack driven through trusted, signed Windows tools, where a
clean hash proves nothing and only context gives the attacker away.

Three of the signals that make that possible are not readable at medium integrity, because
Windows deliberately protects them:

- a real-time kernel trace session,
- the image path of a protected process,
- the machine-wide auto-start configuration.

A packaged application may not declare `requireAdministrator` for itself, and it should
not: the monitor's user interface, its rules, its charts and its event log have no business
running elevated, and for the great majority of a session nothing elevated is needed at
all. So the design puts **only** the three protected operations in a separate executable,
`MeowSecurity.Engine`, started on demand through the `runas` verb behind the standard
Windows consent prompt — and `allowElevation` is what permits a packaged application to
start such a process.

The capability is therefore not a convenience. It is what allows the product to be *less*
privileged than the obvious alternatives, which is the reason the design took this shape.

### What else was explored

| Alternative | Why it was rejected |
|---|---|
| **Run the whole application elevated** | Not permitted for a packaged application, and wrong regardless: it would put the entire user interface, the parsing of process command lines and the rendering layer at high integrity, when three narrow operations are what actually need it. |
| **A Windows service running as SYSTEM** | Strictly more dangerous, not less. It would be permanently elevated, running with no user present, surviving every reboot, and reachable for as long as the machine is on. The present design is elevated only while the user has the monitor open, and exits with it. |
| **A scheduled task with highest privileges** | The same objection, plus it hides the elevation from the user entirely. The consent prompt is a feature: the person decides, each session, whether to grant the deeper view. |
| **Ship without the elevated parts** | This was implemented and it does run — see section 2 for exactly what is lost. It is offered as the unelevated mode, and the Settings page always states which parts are limited. It is not sufficient as the only mode, for the reasons below. |

## 2. The functionality that requires it, and why less privileged alternatives fall short

The application runs unelevated by default and stays useful there. These three capabilities
are what the elevated helper adds, and each has been measured against its unprivileged
fallback:

**Live capture of process creation from the kernel.** Opening a real-time ETW kernel
session requires `SeDebugPrivilege`; Windows grants it to no medium-integrity caller. The
unprivileged fallback is polling, and polling has a floor: a one-second sweep cannot see a
process that lives for 300 ms. That is not a hypothetical gap — a downloaded-and-executed
one-liner is precisely the shape this product exists to catch, and it is precisely the
shape that a poll misses. The difference is not resolution, it is whether the detection
happens at all.

**Reading the image path of a protected process.** `QueryFullProcessImageNameW` needs
`PROCESS_QUERY_LIMITED_INFORMATION`, which a protected or SYSTEM process does not give a
medium-integrity caller. Without it those rows have no path, no signature and no publisher
— the fields every behavioural rule reasons over. A process the monitor cannot describe is
a blind spot in a product whose entire claim is that it describes processes.

**Changing a machine-wide auto-start entry.** `HKLM` Run keys and service `Start` values
are not writable at medium integrity. The product can already *find* what starts by itself
without elevation; what it cannot do is act. Reporting a hostile auto-start entry and then
being unable to switch it off is a poor answer to give a person who has just been told
their machine is compromised.

Per-user auto-start entries are handled by the application itself, unelevated, precisely
because they do not require more. Nothing is routed through the helper that the
application can do on its own.

## 3. Limiting access and scope — least privilege in practice

Implemented in `MeowSecurity.Engine/Program.cs` and `MeowSecurity.Core/Ipc/Protocol.cs`:

- **A closed verb list, not a command channel.** The helper accepts five messages:
  `Ping`, `StartCapture`, `StopCapture`, `SetAutorun`, `Shutdown`. There is no verb that
  runs a program, opens a file, writes a registry value it is handed, or evaluates
  anything the client sends. Any unrecognised message is refused.
- **It names, it does not describe.** `SetAutorun` takes the *identity* of an entry the
  application already discovered. The helper re-scans the machine itself and acts only on
  an entry it found in that scan. No path, command line or registry key crosses the
  boundary, so there is nothing for a caller to talk the elevated side into writing.
- **The endpoint is not public.** The named pipe is created with an explicit ACL granting
  read and write to the interactive user's SID alone — not `Everyone`, not `Users` — and
  with a single server instance.
- **The caller is verified, not assumed.** Same-user is not accepted as proof: any program
  running as the user would pass it. The helper resolves the client's process id with
  `GetNamedPipeClientProcessId`, reads that process's image path, and refuses unless it is
  `MeowSecurity.exe` in the helper's own directory.
- **It cannot be left running.** If no client connects within 45 seconds it exits rather
  than lingering elevated — the case that occurs when the application dies between
  launching the helper and reaching it. Once connected, a closed or vanished client ends
  the loop and the process exits. It is not registered to auto-start and holds no
  persistent state.

## 4. Safeguards against misuse, unintended behaviour and user harm

- **Elevation is always the user's decision.** The helper starts through `runas`, so the
  Windows consent prompt appears. The application is never silently elevated, and
  declining is a supported outcome: it continues in unelevated mode and says so.
- **A refused connection is recorded.** Attempts by a caller that is not the application
  are written to `engine.log` with the reason and the rejected image path. An elevated
  endpoint someone is trying is something the machine's owner should be able to see.
- **Destructive actions do not live here.** Ending a process and removing a startup entry
  are confirmed by the user in the application, and the disable path writes the same
  `StartupApproved` flags Task Manager uses — so a change made here is visible to Windows'
  own tools and can be undone from either side. Nothing is hidden and nothing is one-way.
- **No network, anywhere in the product.** There is no update channel, no telemetry, no
  account, no key and no server, in the helper or the application. The elevated process
  cannot be instructed by anything off the machine, because nothing off the machine can
  reach it. See `PRIVACY.md`.
- **The code is public and the licence keeps it that way.** GPL-3.0 means every shipped
  build's source is available for exactly this kind of scrutiny.

## 5. Statement of assurance

`allowElevation` will be used solely to launch `MeowSecurity.Engine`, the helper described
above, for the three purposes stated in section 2: opening a kernel trace session, reading
protected process images, and enabling or disabling an auto-start entry at the user's
explicit request.

The elevated helper writes to exactly two locations:

| Path | What is written |
|---|---|
| `%LOCALAPPDATA%\MeowSecurity\engine.log` | Its own diagnostic lines, including refused connections. |
| `StartupApproved` flags, `HKLM` Run keys, service `Start` values, scheduled-task `Enabled` | Only for an entry the user chose to enable or disable, one entry per request. |

It writes nowhere else, transmits nothing, and will not be extended to further privileged
operations without a fresh justification to the Store Certification team.
