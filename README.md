# RDP-Guard

**Harden an internet-exposed Windows RDP endpoint and auto-ban brute-force scanners — with all alerting kept local.**

RDP-Guard is a small, self-contained PowerShell toolkit for the common-but-risky
situation where you *must* expose Remote Desktop to the public internet (you
connect from changing locations, can't run a VPN client from the remote side, and
can't geo/IP allow-list). Changing the RDP port alone is just
security-through-obscurity — mass scanners still find it within hours. RDP-Guard
adds real defense-in-depth and a fail2ban-style auto-blocker.

> ⚠️ **Reality check:** an exposed RDP port is inherently riskier than a VPN-gated
> one. RDP-Guard reduces that risk substantially; it does not make it zero. If you
> *can* use a VPN/RD-Gateway, do that instead. If you can't, this is for you — and
> you should still add [MFA](#optional-mobile-approval--mfa).

## Features

- **Firewall hygiene** — disables stale default RDP rules, replaces ad-hoc rules
  with one clean inbound rule on your chosen port.
- **Auto-blocker** — a SYSTEM scheduled task watches failed logins and bans
  offending IPs via a single, self-maintaining firewall rule.
  - Reads **both** the Security log (Event 4625) **and** the RDP core log
    (`RdpCoreTS/Operational` Event 140) — so it catches scanners rejected at the
    NLA pre-auth stage that never generate a 4625.
  - **Real ban expiry** with **escalating** bans for repeat offenders.
  - **Correct CIDR** whitelisting (never blocks your LAN/loopback).
  - **One** firewall rule, rebuilt from a JSON state file — no rule sprawl.
- **Hardening** — strong password policy, High RDP encryption, NLA + TLS, session
  idle/disconnect timeouts, and a larger Security log so floods don't roll events.
- **Local-only alerting** — every ban/unban is written to a dedicated `RDP-Guard`
  Windows Event Log, and optional **Windows toast popups** fire on a ban or a
  successful RDP login. Nothing is sent to any external service.
- **Admin tooling** — list/inspect bans, manually block/unblock, and an
  on-demand activity report (top offenders, targeted usernames, *successful*
  logins) via `Show-Activity` / `View-Activity.cmd`.

## Requirements

- Windows 10/11 **Pro** (or Server). Works under both Windows PowerShell 5.1 and
  PowerShell 7+ (event logging uses the `System.Diagnostics.EventLog` .NET API so
  it behaves the same on either).
- Administrator rights to install.

## Install

```powershell
# from an elevated PowerShell
git clone https://github.com/smartboy223/RDP-Guard.git C:\Security\RDP-Guard
powershell -ExecutionPolicy Bypass -File "C:\Security\RDP-Guard\Install.ps1"
```

The installer applies the firewall changes, hardening, creates the `RDP-Guard`
event log, and registers the scheduled task (runs at startup + every minute).

**Set your port first:** edit `rdpPort` in [`config.json`](#configuration) to match
your RDP port *before* installing (default `4002`).

Options:
- `-SkipHardening` — install only the firewall cleanup + auto-blocker.
- `-DisableBuiltinAdmin` — also disable the built-in Administrator account
  (only if you have another working admin account).

### Validate the install

After installing, confirm everything works (double-click **`Validate-Setup.cmd`**,
or run `Test-RDPGuard.ps1`). It checks the config, event log, scheduled tasks,
firewall rule, and listening port, then runs a **live ban-pipeline self-test**
(blocks a reserved TEST-NET IP → verifies it lands in the state file, firewall
rule, and event log → unblocks it) and shows two example toasts. You should see a
`PASS / WARN / FAIL` summary ending in "RDP-Guard is installed and working."

> On a brand-new install the engine's "last run result" may show a `WARN` until the
> task's first scheduled tick — that's expected.

## Usage

```powershell
Import-Module "C:\Security\RDP-Guard\RDP-Guard.Admin.psm1" -Force

Get-RDPGuardBans                 # currently active bans
Get-RDPGuardBans -IncludeExpired # full history
Get-RDPGuardReport -Hours 24     # offenders, targeted usernames, SUCCESSFUL logins
Block-RDPGuardIP   -IP 1.2.3.4 -Permanent
Unblock-RDPGuardIP -IP 1.2.3.4
```

**View activity anytime:** double-click **`View-Activity.cmd`** (prompts for admin)
for a one-shot report, or:

```powershell
powershell -ExecutionPolicy Bypass -File "C:\Security\RDP-Guard\Show-Activity.ps1" -Hours 72
```

**Raw ban/unban log:**

```powershell
Get-WinEvent -LogName 'RDP-Guard' -MaxEvents 20
```

> Tip: check the **successful logins** section of the report regularly — if a login
> wasn't you, you'll see it there (with the source IP).

### Local toast alerts

With `alerts.toast` enabled in `config.json` (default), `Install.ps1` registers two
small user-context, event-triggered tasks that pop a native Windows toast:

- **On ban** — when the engine blocks an IP.
- **On RDP login** — when a session authenticates (your "someone just logged in"
  signal; if it wasn't you, investigate).

These run in your interactive session (the engine runs as SYSTEM and can't draw to
your desktop), use the built-in WinRT toast API with a tray-balloon fallback, and
send nothing off the machine. Toggle them with `alerts.onBan` / `alerts.onLogin`.

## Configuration

All tunables live in `config.json`; the engine re-reads it every run (no restart).

| Key | Default | Meaning |
|-----|---------|---------|
| `rdpPort` | `4002` | Your RDP listening port |
| `threshold` | `6` | Failures from one IP before a ban |
| `lookbackMinutes` | `15` | Sliding window for counting failures |
| `banHours` | `24` | Base ban length |
| `escalation` | ×2, cap 720h | Repeat offenders get longer bans |
| `whitelist` | RFC1918 + loopback | Never-block ranges (CIDR supported) |
| `retentionDays` | `30` | How long expired records are kept (for escalation memory) |
| `hardening.*` | — | Values applied by `Install.ps1` |

## How it works

```
                 ┌──────────────────────────── every 1 min (SYSTEM task) ───────────────┐
 Security 4625 ─▶│ read failures in window ─▶ count by IP ─▶ ≥ threshold & not          │
 RdpCoreTS 140 ─▶│   whitelisted ─▶ add/extend ban in state.json (escalating)           │
                 │ expire old bans ─▶ rebuild ONE firewall block rule ─▶ log to EventLog │
                 └──────────────────────────────────────────────────────────────────────┘
```

Block rules take precedence over allow rules in Windows Firewall, so a banned IP
cannot reach the RDP port even though the port is open to everyone else.

## Optional: mobile approval / MFA

The single highest-value upgrade for an exposed endpoint is **multi-factor auth at
logon**, because it works with the stock RDP client (`mstsc`) and needs nothing
installed on the device you connect *from*:

- **[Duo Authentication for Windows Logon](https://duo.com/docs/rdp)** — tap-to-approve
  push on your phone after the password. Free for personal use (≤10 users).
- **[multiOTP Credential Provider](https://github.com/multiOTP/multiOTPCredentialProvider)** —
  fully open-source / self-hosted; a 6-digit code from any authenticator app.

These are separate products (not bundled here) precisely so RDP-Guard stays
self-contained and local-only. Pick one if you want "confirm from my phone to log
in."

## Security notes & trade-offs

- **Account lockout vs. DoS:** if Windows account lockout is enabled (recommended),
  an attacker who guesses your *username* can lock that account (a nuisance/DoS).
  Mitigate with a **non-obvious RDP username** and let RDP-Guard ban the source IP
  fast. Don't expose the built-in `Administrator`.
- **Don't RDP as an admin if you can avoid it.** Prefer a dedicated standard user
  in *Remote Desktop Users*.
- **Locking yourself out:** the threshold (6) is above typical typo counts, and
  private ranges are never blocked. If your public IP is ever banned, clear it from
  a console/another machine — see below.

### "I locked myself out"

```powershell
Import-Module "C:\Security\RDP-Guard\RDP-Guard.Admin.psm1" -Force
Unblock-RDPGuardIP -IP <your-public-ip>
# or clear everything in a pinch:
Get-NetFirewallRule -DisplayName 'RDP-Guard-Block' | Remove-NetFirewallRule
```
(A bad password lockout is more likely — that's the OS account-lockout policy;
wait out the lockout window or reset from the console.)

## Uninstall

```powershell
powershell -ExecutionPolicy Bypass -File "C:\Security\RDP-Guard\Uninstall.ps1"
# -RemoveEventLog  also delete the RDP-Guard log
# -RemoveAllowRule also remove the RDP allow rule (closes the port!)
```
Hardening (password policy, encryption, timeouts) is intentionally left in place.

## Files

| File | Purpose |
|------|---------|
| `Install.ps1` / `Uninstall.ps1` | Setup / teardown |
| `RDP-Guard.ps1` | Auto-blocker engine (run by the scheduled task; `-DryRun` to test) |
| `RDP-Guard.Common.ps1` | Shared helpers (config/state/CIDR/firewall/logging) |
| `RDP-Guard.Admin.psm1` | `Get-RDPGuardBans` / `Block` / `Unblock` / `Get-RDPGuardReport` |
| `Show-Activity.ps1` / `View-Activity.cmd` | On-demand activity viewer |
| `Test-RDPGuard.ps1` / `Validate-Setup.cmd` | End-to-end install validation / self-test |
| `RDP-Guard.Toast.ps1` | Local toast popup shown by the alert tasks |
| `config.json` | All tunables |
| `state.json` | Persisted bans (created at runtime; git-ignored) |

## Disclaimer

Provided as-is, no warranty. You are responsible for testing it in your own
environment and for the security of your systems. Exposing RDP to the internet
carries inherent risk.

## License

[MIT](LICENSE)
