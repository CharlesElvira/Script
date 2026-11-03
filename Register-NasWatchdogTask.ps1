<#
.SYNOPSIS
    Registers (or replaces) the "NAS Watchdog" scheduled task so that only one
    instance can run at a time and it checks every minute.

.EXAMPLE
    .\Register-NasWatchdogTask.ps1 -NasHost 192.168.1.50 -NasPort 5000
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $NasHost,
    [int]    $NasPort = 0,
    [string] $TaskName = 'NAS Watchdog',
    [string] $ScriptPath = (Join-Path $PSScriptRoot 'Nas-Watchdog.ps1')
)

if (-not (Test-Path $ScriptPath)) { throw "Script not found: $ScriptPath" }

$argList = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$ScriptPath`" -NasHost $NasHost"
if ($NasPort -gt 0) { $argList += " -NasPort $NasPort" }

$action  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $argList
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date `
           -RepetitionInterval (New-TimeSpan -Minutes 1) `
           -RepetitionDuration (New-TimeSpan -Days 3650)

# IgnoreNew = never start a second copy while one is still running.
$settings = New-ScheduledTaskSettingsSet `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 2) `
    -StartWhenAvailable `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest

# Remove any older copies so there is exactly one task with one trigger.
Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue |
    Unregister-ScheduledTask -Confirm:$false

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Settings $settings -Principal $principal | Out-Null

Write-Host "Registered task '$TaskName' running every minute: $argList"
Write-Host "Log:   $env:ProgramData\NasWatchdog\watchdog.log"
Write-Host "State: $env:ProgramData\NasWatchdog\state.json"
