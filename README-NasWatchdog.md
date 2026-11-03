# NAS Watchdog

Checks the NAS every minute from the laptop and power-cycles it through the
UPS network outlet only when it is really down.

## Why this version exists

On 2026-11-03 the previous watchdog power-cycled the NAS every 30 seconds.
It checked every minute and rebooted on any failed check, but the NAS needs
several minutes to boot, so every check during boot looked like "NAS down" and
triggered another power cycle. This version waits for the boot to finish and
adds several other guards.

## Guards

| Guard | Default | Parameter |
|---|---|---|
| Boot grace after a power cycle | 10 min | `-BootGraceMinutes` |
| Consecutive failed checks before acting | 3 | `-FailuresBeforeReboot` |
| Minimum time between two power cycles | 15 min | `-MinMinutesBetweenReboots` |
| Maximum power cycles per rolling 24 h | 3 | `-MaxRebootsPerDay` |
| Laptop must reach its gateway, else the run is skipped | on | `-GatewayHost ""` to disable |

Set `-BootGraceMinutes` to your NAS boot time plus a safety margin. Time a
cold boot once and add 3 to 5 minutes.

## Setup

1. Open `Nas-Watchdog.ps1` and paste your existing UPS outlet command into
   the `Invoke-NasPowerCycle` function. Until you do, the script refuses to
   power-cycle and logs an error instead.
2. Test without touching the UPS:
   ```powershell
   .\Nas-Watchdog.ps1 -NasHost 192.168.1.50 -NasPort 5000 -DryRun -Verbose
   ```
3. Register the task (run as Administrator). This removes any older task with
   the same name so only one instance exists:
   ```powershell
   .\Register-NasWatchdogTask.ps1 -NasHost 192.168.1.50 -NasPort 5000
   ```

## Files written at runtime

- `C:\ProgramData\NasWatchdog\watchdog.log` - one line per decision
  (`OK`, `DOWN`, `WAIT`, `HOLD`, `STOP`, `CYCLE`, `SKIP`, `ERROR`).
- `C:\ProgramData\NasWatchdog\state.json` - failure counter and reboot history.
  Delete it to reset the counters.

## If the NAS stays down

After 3 power cycles in 24 hours the watchdog logs `STOP` and does nothing
more. That means power cycling is not fixing the problem. Look at the NAS.
