<#
.SYNOPSIS
    NAS watchdog with a boot grace period. Runs every minute from Task Scheduler
    and power-cycles the NAS through the UPS outlet ONLY when it is genuinely down.

.DESCRIPTION
    Safeguards against the reboot loop seen on 2026-11-03 (NAS power-cycled every
    30 seconds because the next check ran while the NAS was still booting):

      1. Boot grace period   - after a power cycle, nothing happens for
                               -BootGraceMinutes (default 10) while the NAS boots.
      2. Consecutive failures - the NAS must be unreachable on
                               -FailuresBeforeReboot consecutive runs (default 3)
                               before any action is taken. One lost ping is ignored.
      3. Laptop network check - if the default gateway cannot be reached, the
                               laptop is offline, so the run is skipped and does
                               not count as a NAS failure.
      4. Cooldown             - at least -MinMinutesBetweenReboots (default 15)
                               between two power cycles.
      5. Daily cap            - no more than -MaxRebootsPerDay (default 3) power
                               cycles in any rolling 24 hours. If the NAS does not
                               come back after that, something else is wrong and
                               a human must look at it.
      6. Logging              - every decision is written to the log file.

    State (failure counter, reboot history) is kept in a small JSON file so it
    survives between runs of the scheduled task.

.PARAMETER NasHost
    IP address or host name of the NAS.
.PARAMETER NasPort
    Optional TCP port to test as well (e.g. 445 for SMB, 5000 for Synology DSM,
    8080 for QNAP). If given, the NAS is considered UP when ping OR the TCP port
    answers. Useful when ICMP is filtered.
.PARAMETER GatewayHost
    Host used to prove the laptop itself is online. Defaults to the laptop's
    default gateway ("auto"). Pass "" to skip this check.
.PARAMETER DryRun
    Log what would happen but never actually power-cycle.

.EXAMPLE
    .\Nas-Watchdog.ps1 -NasHost 192.168.1.50 -NasPort 5000
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $NasHost,

    [int]    $NasPort = 0,

    [string] $GatewayHost = 'auto',

    [int]    $PingCount = 3,
    [int]    $FailuresBeforeReboot = 3,
    [int]    $BootGraceMinutes = 10,
    [int]    $MinMinutesBetweenReboots = 15,
    [int]    $MaxRebootsPerDay = 3,

    [string] $StateFile = (Join-Path $env:ProgramData 'NasWatchdog\state.json'),
    [string] $LogFile   = (Join-Path $env:ProgramData 'NasWatchdog\watchdog.log'),

    [switch] $DryRun
)

$ErrorActionPreference = 'Stop'

# -----------------------------------------------------------------------------
# POWER CYCLE COMMAND
# Paste the command you already use to cut and restore the UPS outlet in the
# function below. It is the ONLY place that touches the UPS. Everything else in
# this script decides *whether* it is safe to call it.
# -----------------------------------------------------------------------------
function Invoke-NasPowerCycle {
    # Examples (uncomment / adapt the one that matches your UPS):
    #
    # APC / Schneider network card via SNMP (outlet 1 = reboot):
    #   & snmpset -v1 -c private 192.168.1.10 .1.3.6.1.4.1.318.1.1.4.4.2.1.3.1 i 3
    #
    # Eaton / generic PDU via HTTP:
    #   Invoke-WebRequest -Uri 'http://192.168.1.10/outlet?1=CCL' -Credential $cred
    #
    # Two-step off/on with a pause:
    #   & snmpset ... i 2          # outlet off
    #   Start-Sleep -Seconds 15
    #   & snmpset ... i 1          # outlet on

    throw 'Invoke-NasPowerCycle is not configured yet. Paste your UPS outlet command into Nas-Watchdog.ps1.'
}

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
function Write-Log {
    param([string] $Message)
    $line = '{0:yyyy-MM-dd HH:mm:ss} {1}' -f (Get-Date), $Message
    $dir = Split-Path -Parent $LogFile
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
    Write-Verbose $line
}

function Get-State {
    if (Test-Path $StateFile) {
        try {
            $s = Get-Content -Path $StateFile -Raw | ConvertFrom-Json
            return [pscustomobject]@{
                ConsecutiveFailures = [int] $s.ConsecutiveFailures
                LastRebootUtc       = if ($s.LastRebootUtc) { [datetime] $s.LastRebootUtc } else { $null }
                RebootHistoryUtc    = @($s.RebootHistoryUtc | ForEach-Object { [datetime] $_ })
            }
        }
        catch {
            Write-Log "WARN  state file unreadable, starting fresh: $($_.Exception.Message)"
        }
    }
    return [pscustomobject]@{
        ConsecutiveFailures = 0
        LastRebootUtc       = $null
        RebootHistoryUtc    = @()
    }
}

function Save-State {
    param($State)
    $dir = Split-Path -Parent $StateFile
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $out = [ordered]@{
        ConsecutiveFailures = $State.ConsecutiveFailures
        LastRebootUtc       = if ($State.LastRebootUtc) { $State.LastRebootUtc.ToString('o') } else { $null }
        RebootHistoryUtc    = @($State.RebootHistoryUtc | ForEach-Object { $_.ToString('o') })
    }
    $out | ConvertTo-Json | Set-Content -Path $StateFile -Encoding UTF8
}

function Test-Host {
    param([string] $HostName, [int] $Port = 0)

    # ICMP
    $pingOk = $false
    try {
        $pingOk = Test-Connection -ComputerName $HostName -Count $PingCount -Quiet -ErrorAction Stop
    }
    catch { $pingOk = $false }
    if ($pingOk) { return $true }

    # Optional TCP port, for when ICMP is filtered.
    if ($Port -gt 0) {
        $client = New-Object System.Net.Sockets.TcpClient
        try {
            $async = $client.BeginConnect($HostName, $Port, $null, $null)
            if ($async.AsyncWaitHandle.WaitOne(3000, $false)) {
                $client.EndConnect($async)
                return $true
            }
        }
        catch { }
        finally { $client.Close() }
    }
    return $false
}

function Get-DefaultGateway {
    try {
        $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
                 Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1
        return $route.NextHop
    }
    catch { return $null }
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
$now   = (Get-Date).ToUniversalTime()
$state = Get-State

# 1. Boot grace period: never act while the NAS may still be booting.
if ($state.LastRebootUtc) {
    $sinceReboot = $now - $state.LastRebootUtc
    if ($sinceReboot.TotalMinutes -lt $BootGraceMinutes) {
        $left = [math]::Ceiling($BootGraceMinutes - $sinceReboot.TotalMinutes)
        if (Test-Host -HostName $NasHost -Port $NasPort) {
            Write-Log "OK    NAS is back $([int]$sinceReboot.TotalMinutes) min after power cycle"
            $state.ConsecutiveFailures = 0
            Save-State $state
        }
        else {
            Write-Log "WAIT  NAS not reachable yet, still in boot grace period ($left min left)"
        }
        exit 0
    }
}

# 2. Is the laptop itself online? If not, this says nothing about the NAS.
if ($GatewayHost -eq 'auto') { $GatewayHost = Get-DefaultGateway }
if ($GatewayHost) {
    if (-not (Test-Host -HostName $GatewayHost)) {
        Write-Log "SKIP  gateway $GatewayHost unreachable, laptop is offline; not counting as NAS failure"
        exit 0
    }
}

# 3. Check the NAS.
if (Test-Host -HostName $NasHost -Port $NasPort) {
    if ($state.ConsecutiveFailures -gt 0) {
        Write-Log "OK    NAS reachable again after $($state.ConsecutiveFailures) failed check(s)"
        $state.ConsecutiveFailures = 0
        Save-State $state
    }
    exit 0
}

# 4. NAS down: count it.
$state.ConsecutiveFailures++
Write-Log "DOWN  NAS $NasHost unreachable ($($state.ConsecutiveFailures)/$FailuresBeforeReboot)"
Save-State $state

if ($state.ConsecutiveFailures -lt $FailuresBeforeReboot) { exit 0 }

# 5. Enough failures. Apply cooldown and daily cap before acting.
if ($state.LastRebootUtc) {
    $sinceReboot = $now - $state.LastRebootUtc
    if ($sinceReboot.TotalMinutes -lt $MinMinutesBetweenReboots) {
        Write-Log "HOLD  last power cycle was $([int]$sinceReboot.TotalMinutes) min ago, cooldown is $MinMinutesBetweenReboots min"
        exit 0
    }
}

$recent = @($state.RebootHistoryUtc | Where-Object { ($now - $_).TotalHours -lt 24 })
if ($recent.Count -ge $MaxRebootsPerDay) {
    Write-Log "STOP  already $($recent.Count) power cycle(s) in the last 24 h (cap $MaxRebootsPerDay). NAS needs manual attention."
    exit 0
}

# 6. Power cycle.
if ($DryRun) {
    Write-Log "DRY   would power-cycle NAS now"
}
else {
    try {
        Invoke-NasPowerCycle
        Write-Log "CYCLE power-cycled NAS via UPS outlet; waiting $BootGraceMinutes min for boot"
    }
    catch {
        Write-Log "ERROR power cycle failed: $($_.Exception.Message)"
        exit 1
    }
}

$state.LastRebootUtc       = $now
$state.RebootHistoryUtc    = @($recent) + @($now)
$state.ConsecutiveFailures = 0
Save-State $state
exit 0
