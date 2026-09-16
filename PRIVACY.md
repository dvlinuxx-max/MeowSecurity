# Privacy Policy — Meow Security

**Last updated:** 16 September 2026
**Publisher:** Mohammed Abd Alrahman — [mohmadev.com](https://mohmadev.com)

## The short version

Meow Security collects nothing, sends nothing, and has no servers.

The application runs entirely on your computer. It contains no analytics, no
telemetry, no crash reporting service, no advertising, and no accounts. It makes
no network connections of any kind.

## What the application stores, and where

Everything it writes stays on your machine, in
`%LOCALAPPDATA%\MeowSecurity`:

| File | What it holds |
|---|---|
| `settings.json` | Your interface preferences: theme, notification and sound switches, background monitoring, health monitoring. |
| `events.jsonl` | The security events the monitor recorded: time, process name, image path, command line, which rule fired. Capped at 2000 entries. |
| `autorun-changes.json` | A record of startup entries you disabled or removed through the app, so the change can be undone. |
| `crash.log` | Written only if the application fails, to explain why. |

None of this is transmitted anywhere. You can delete any of these files at any
time; the application will recreate what it needs with default values.

The event log can contain command lines of programs running on your computer,
which may include file paths or arguments you consider sensitive. It is stored in
your own user profile, readable only by your Windows account, and it never leaves
the machine. The Events page has a "clear log" button.

## What the application reads

To do its job, Meow Security reads information about your own system: running
processes and their command lines, digital signatures of program files, network
connections and their byte counts, entries that start automatically with Windows,
and processor and memory usage. It reads this locally and reports it to you only.

## Permissions

The application asks for administrator rights only when you enable a feature that
requires them — the live kernel event capture, disabling a machine-wide startup
entry, or registering itself to start with Windows. It works without them, with
reduced visibility, and it tells you which parts are limited.

## Children

The application is not directed at children and collects no personal information
from anyone.

## Changes

Any change to this policy will be published at this page's address, with the date
above updated.

## Contact

Questions about privacy or the application: open an issue at
[github.com/dvlinuxx-max](https://github.com/dvlinuxx-max) or through
[mohmadev.com](https://mohmadev.com).
